mod smoke;
use smoke::{seed_smoke, smoke_sequence};
mod editors;
mod home;
mod nodes;
mod settings;
mod startup;
mod subscriptions;
mod typography;

use adw::prelude::*;
use aerobox_for_linux::{
    engine::Service,
    model::{self, RuleSet, Subscription},
    network, platform,
};
use anyhow::{Context, Result};
use gtk::{gio, glib};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    path::{Path, PathBuf},
    rc::Rc,
    sync::{Arc, mpsc},
    time::Duration,
};

pub use startup::recover_store;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Page {
    Home,
    Nodes,
    Subscriptions,
    Rules,
    Connections,
    Logs,
    Settings,
}
impl Page {
    const ALL: [Self; 7] = [
        Self::Home,
        Self::Nodes,
        Self::Subscriptions,
        Self::Rules,
        Self::Connections,
        Self::Logs,
        Self::Settings,
    ];
    fn title(self) -> &'static str {
        match self {
            Self::Home => "首页",
            Self::Nodes => "节点",
            Self::Subscriptions => "订阅",
            Self::Rules => "规则",
            Self::Connections => "连接",
            Self::Logs => "日志",
            Self::Settings => "设置",
        }
    }
    fn icon(self) -> &'static str {
        match self {
            Self::Home => "go-home-symbolic",
            Self::Nodes => "network-wireless-symbolic",
            Self::Subscriptions => "folder-download-symbolic",
            Self::Rules => "view-list-bullet-symbolic",
            Self::Connections => "network-transmit-receive-symbolic",
            Self::Logs => "utilities-terminal-symbolic",
            Self::Settings => "preferences-system-symbolic",
        }
    }
}

pub fn run(
    service: Arc<Service>,
    smoke: Option<PathBuf>,
    resume: bool,
) -> (glib::ExitCode, Option<bool>) {
    if smoke.is_some()
        && let Err(e) = seed_smoke(&service)
    {
        eprintln!("smoke fixture: {e:#}");
        return (glib::ExitCode::FAILURE, None);
    }
    let app = adw::Application::builder()
        .application_id(platform::APP_ID)
        .flags(if smoke.is_some() {
            gio::ApplicationFlags::NON_UNIQUE
        } else {
            gio::ApplicationFlags::FLAGS_NONE
        })
        .build();
    let failed = Rc::new(Cell::new(false));
    let activate_failed = failed.clone();
    let activate_service = service.clone();
    let relaunch = Rc::new(Cell::new(None));
    let activate_relaunch = relaunch.clone();
    app.connect_activate(move |app| {
        if let Some(window) = app.active_window() {
            window.present();
            return;
        }
        let display = gtk::gdk::Display::default().expect("Wayland display");
        let resource = gio::Resource::from_data(&glib::Bytes::from_static(include_bytes!(
            concat!(env!("OUT_DIR"), "/aerobox.gresource")
        )))
        .expect("embedded application resources");
        gio::resources_register(&resource);
        gtk::IconTheme::for_display(&display)
            .add_resource_path("/io/github/imengying/AeroBoxForLinux/icons");
        let provider = gtk::CssProvider::new();
        provider.load_from_resource("/io/github/imengying/AeroBoxForLinux/styles/main.css");
        gtk::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
        if smoke.is_some() {
            // A desktop may omit font DPI. Exercise this real layout failure
            // even when the test compositor normally provides a valid value.
            gtk::Settings::default()
                .expect("GTK settings")
                .set_gtk_xft_dpi(-1);
            gtk::Settings::default()
                .expect("GTK settings")
                .set_gtk_enable_animations(false);
        }
        let ui = Ui::new(app, activate_service.clone(), activate_relaunch.clone());
        ui.smoke_dir.replace(
            smoke
                .as_ref()
                .and_then(|path| path.parent().map(Path::to_owned)),
        );
        ui.window.present();
        if let Some(path) = smoke.clone() {
            glib::spawn_future_local(smoke_sequence(ui.clone(), path, activate_failed.clone()));
        } else {
            if resume {
                ui.task_result(
                    |s| s.start(),
                    |ui, result| {
                        ui.refresh(Page::Home);
                        if let Err(error) = result {
                            ui.error("恢复连接失败", format!("{error:#}"));
                        }
                    },
                );
            }
            ui.start_subscription_updates();
        }
    });
    let monitor = Arc::downgrade(&service);
    std::thread::spawn(move || {
        loop {
            let Some(service) = monitor.upgrade() else {
                break;
            };
            service.poll();
            drop(service);
            std::thread::sleep(Duration::from_millis(500));
        }
    });
    let result = app.run_with_args::<&str>(&[]);
    let result = if failed.get() {
        glib::ExitCode::FAILURE
    } else {
        result
    };
    (result, relaunch.get())
}

struct Ui {
    relaunch: Rc<Cell<Option<bool>>>,
    typography: typography::Typography,
    window: adw::ApplicationWindow,
    service: Arc<Service>,
    toast: adw::ToastOverlay,
    /// The toast currently on screen, so a new notification can replace it
    /// instead of stacking a second one underneath and clipping both.
    active_toast: RefCell<Option<adw::Toast>>,
    body: gtk::Box,
    window_size: RefCell<(i32, i32)>,
    window_size_generation: Cell<u64>,
    scroll: gtk::ScrolledWindow,
    floating: gtk::Overlay,
    home_action: RefCell<Option<gtk::Button>>,
    nodes_action: RefCell<Option<gtk::Button>>,
    settings_action: RefCell<Option<gtk::Button>>,
    nav: gtk::ListBox,
    nav_scroll: gtk::ScrolledWindow,
    syncing_navigation: Cell<bool>,
    page: Cell<Page>,
    split: adw::OverlaySplitView,
    jobs: Cell<usize>,
    last_generation: Cell<Option<u64>>,
    subscription_revision: Cell<u64>,
    subscription_update_pending: Cell<bool>,
    dashboard: RefCell<Option<Rc<home::Dashboard>>>,
    log_buffer: RefCell<Option<gtk::TextBuffer>>,
    settings_panel: RefCell<Option<Rc<settings::SettingsPanel>>>,
    pending_leave: RefCell<Option<Rc<dyn Fn()>>>,
    settings_prompt: RefCell<Option<adw::AlertDialog>>,
    smoke_dir: RefCell<Option<PathBuf>>,
    node_panel: RefCell<Option<Rc<nodes::NodesPanel>>>,
    /// Last successful exit-IP probe together with the connection/selection key it
    /// was taken for. Page visits reuse it; a node change misses the key.
    last_detected: RefCell<Option<(home::ExitIpKey, network::NetworkInfo)>>,
    detecting: RefCell<Option<home::ExitIpKey>>,
    /// Identifies the latest probe even when two requests use the same route.
    detect_count: Cell<u64>,
}

impl Ui {
    fn new(
        app: &adw::Application,
        service: Arc<Service>,
        relaunch: Rc<Cell<Option<bool>>>,
    ) -> Rc<Self> {
        const MIN_WIDTH: i32 = 480;
        const MIN_HEIGHT: i32 = 400;
        let settings = service.snapshot().settings;
        apply_theme(&settings.theme);
        let typography = typography::Typography::new(settings.font_size);
        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("AeroBox")
            .width_request(MIN_WIDTH)
            .height_request(MIN_HEIGHT)
            .default_width(settings.width.max(MIN_WIDTH))
            .default_height(settings.height.max(MIN_HEIGHT))
            .build();
        window.add_css_class("aerobox-window");
        window.set_icon_name(Some(platform::APP_ID));
        let manager = adw::StyleManager::default();
        if manager.is_dark() {
            window.add_css_class("dark");
        }
        let weak_window = window.downgrade();
        manager.connect_dark_notify(move |manager| {
            if let Some(window) = weak_window.upgrade() {
                if manager.is_dark() {
                    window.add_css_class("dark")
                } else {
                    window.remove_css_class("dark")
                }
            }
        });
        let sidebar = gtk::Box::new(gtk::Orientation::Vertical, 0);
        sidebar.add_css_class("app-sidebar");
        let side_header = adw::HeaderBar::new();
        side_header.add_css_class("transparent-header");
        side_header.set_show_end_title_buttons(false);
        side_header.set_title_widget(Some(&gtk::Box::new(gtk::Orientation::Horizontal, 0)));
        // Brand sits in the window's top-left corner, in the sidebar track, so
        // it stays put instead of shifting with the page header contents.
        let brand = gtk::Box::new(gtk::Orientation::Horizontal, 7);
        brand.add_css_class("header-brand");
        brand.set_valign(gtk::Align::Center);
        brand.update_property(&[gtk::accessible::Property::Label("AeroBox")]);
        let data = glib::Bytes::from_static(include_bytes!(
            "../../resources/icons/io.github.imengying.AeroBoxForLinux.png"
        ));
        let texture = gtk::gdk::Texture::from_bytes(&data).expect("embedded PNG icon");
        let mark = gtk::Image::from_paintable(Some(&texture));
        mark.add_css_class("brand-mark");
        brand.append(&mark);
        brand.append(&label("AeroBox", "brand"));
        side_header.pack_start(&brand);
        sidebar.append(&side_header);
        let nav_scroll = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .propagate_natural_height(false)
            .vexpand(true)
            .build();
        nav_scroll.add_css_class("sidebar-scroll");
        sidebar.append(&nav_scroll);
        let nav = gtk::ListBox::new();
        nav.add_css_class("nav-list");
        nav.set_selection_mode(gtk::SelectionMode::Single);
        margin(&nav, 8, 8, 0, 16);
        for page in Page::ALL {
            let row = gtk::ListBoxRow::new();
            let item = gtk::Box::new(gtk::Orientation::Horizontal, 10);
            item.add_css_class("nav-item");
            margin(&item, 12, 8, 0, 0);
            let image = gtk::Image::from_icon_name(page.icon());
            image.add_css_class("nav-icon");
            item.append(&image);
            item.append(&label(page.title(), ""));
            row.set_child(Some(&item));
            nav.append(&row);
        }
        nav.select_row(nav.row_at_index(0).as_ref());
        nav_scroll.set_child(Some(&nav));
        let split = adw::OverlaySplitView::new();
        split.set_sidebar(Some(&sidebar));
        let sidebar_width = sidebar_width(settings.font_size);
        split.set_min_sidebar_width(sidebar_width);
        split.set_max_sidebar_width(sidebar_width);
        split.set_sidebar_width_fraction(0.2);
        let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let header = adw::HeaderBar::new();
        header.add_css_class("transparent-header app-header");
        header.set_title_widget(Some(&gtk::Box::new(gtk::Orientation::Horizontal, 0)));
        content.append(&header);
        let body = gtk::Box::new(gtk::Orientation::Vertical, 16);
        body.set_hexpand(true);
        body.add_css_class("page-content");
        margin(&body, 20, 20, 10, 18);
        let clamp = adw::Clamp::builder()
            .maximum_size(1030)
            .tightening_threshold(850)
            .hexpand(true)
            .child(&body)
            .build();
        let scroll = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .propagate_natural_height(false)
            .propagate_natural_width(false)
            .child(&clamp)
            .vexpand(true)
            .build();
        let floating = gtk::Overlay::new();
        floating.set_child(Some(&scroll));
        floating.set_vexpand(true);
        content.append(&floating);
        split.set_content(Some(&content));
        let toast = adw::ToastOverlay::new();
        toast.set_child(Some(&split));
        window.set_content(Some(&toast));
        let ui = Rc::new(Self {
            relaunch,
            typography,
            window,
            service,
            toast,
            active_toast: RefCell::new(None),
            body,
            window_size: RefCell::new((settings.width, settings.height)),
            window_size_generation: Cell::new(0),
            scroll,
            floating,
            home_action: RefCell::new(None),
            nodes_action: RefCell::new(None),
            settings_action: RefCell::new(None),
            nav,
            nav_scroll,
            syncing_navigation: Cell::new(false),
            page: Cell::new(Page::Home),
            split,
            jobs: Cell::new(0),
            last_generation: Cell::new(None),
            subscription_revision: Cell::new(0),
            subscription_update_pending: Cell::new(false),
            dashboard: RefCell::new(None),
            log_buffer: RefCell::new(None),
            settings_panel: RefCell::new(None),
            pending_leave: RefCell::new(None),
            settings_prompt: RefCell::new(None),
            smoke_dir: RefCell::new(None),
            node_panel: RefCell::new(None),
            last_detected: RefCell::new(None),
            detecting: RefCell::new(None),
            detect_count: Cell::new(0),
        });
        let weak = Rc::downgrade(&ui);
        ui.nav.connect_row_selected(move |_, row| {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let Some(row) = row else {
                return;
            };
            if ui.syncing_navigation.get() {
                return;
            }
            let page = Page::ALL[row.index() as usize];
            if page == ui.page.get() {
                return;
            }
            let destination = ui.clone();
            if ui.confirm_discard_settings(move || destination.navigate(page)) {
                ui.navigate(page);
            }
        });
        let weak = Rc::downgrade(&ui);
        ui.window.connect_close_request(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.save_window_size();
                return ui.confirm_close();
            }
            glib::Propagation::Proceed
        });
        ui.refresh(Page::Home);
        {
            let weak = Rc::downgrade(&ui);
            ui.window.connect_default_width_notify(move |window| {
                if let Some(ui) = weak.upgrade() {
                    if window.is_maximized() || window.is_fullscreen() {
                        return;
                    }
                    ui.observe_window_size();
                }
            });
        }
        {
            let weak = Rc::downgrade(&ui);
            ui.window.connect_default_height_notify(move |window| {
                if let Some(ui) = weak.upgrade() {
                    if window.is_maximized() || window.is_fullscreen() {
                        return;
                    }
                    ui.observe_window_size();
                }
            });
        }
        let weak = Rc::downgrade(&ui);
        glib::timeout_add_local(Duration::from_secs(1), move || {
            let Some(ui) = weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            let status = ui.service.status();
            if ui.last_generation.get() != status.generation
                && (ui.jobs.get() == 0 || ui.page.get() == Page::Home)
            {
                ui.last_generation.set(status.generation);
                if ui.page.get() == Page::Home {
                    ui.refresh(Page::Home);
                } else if let Some(panel) = ui.node_panel.borrow().clone() {
                    panel.refresh(&ui);
                }
            }
            let revision = ui.service.subscription_revision();
            if ui.jobs.get() == 0
                && ui.subscription_revision.replace(revision) != revision
                && matches!(ui.page.get(), Page::Subscriptions | Page::Nodes)
            {
                ui.refresh(ui.page.get());
            }
            if let Some(dashboard) = ui.dashboard.borrow().as_ref() {
                dashboard.tick(&ui);
            }
            if let Some(buffer) = ui.log_buffer.borrow().as_ref() {
                let logs = ui.service.logs();
                if buffer
                    .text(&buffer.start_iter(), &buffer.end_iter(), false)
                    .as_str()
                    != logs
                {
                    buffer.set_text(&logs);
                }
            }
            glib::ControlFlow::Continue
        });
        // Keep the controller alive for the window lifetime without a reference cycle.
        let retained = RefCell::new(Some(ui.clone()));
        ui.window.connect_destroy(move |_| {
            retained.borrow_mut().take();
        });
        ui
    }

    fn notify(&self, message: &str) {
        // Only one toast at a time: stacked toasts overlapped and cut their
        // text off, and a stale "已保存" hides the result that matters.
        if let Some(previous) = self.active_toast.borrow_mut().take() {
            previous.dismiss();
        }
        let toast = adw::Toast::new(message);
        toast.set_timeout(3);
        toast.set_priority(adw::ToastPriority::High);
        self.active_toast.replace(Some(toast.clone()));
        self.toast.add_toast(toast);
    }
    fn error(&self, title: &str, error: impl std::fmt::Display) {
        let dialog = alert_dialog(title, &error.to_string());
        dialog.add_response("close", "知道了");
        dialog.set_default_response(Some("close"));
        dialog.set_close_response("close");
        dialog.present(Some(&self.window));
    }
    fn task<T: Send + 'static>(
        self: &Rc<Self>,
        title: &str,
        work: impl FnOnce(&Service) -> Result<T> + Send + 'static,
        done: impl FnOnce(&Rc<Self>, T) + 'static,
    ) {
        let title = title.to_owned();
        self.task_result(work, move |ui, result| match result {
            Ok(value) => done(ui, value),
            Err(e) => ui.error(&format!("{title}失败"), format!("{e:#}")),
        });
    }
    fn task_result<T: Send + 'static>(
        self: &Rc<Self>,
        work: impl FnOnce(&Service) -> Result<T> + Send + 'static,
        done: impl FnOnce(&Rc<Self>, Result<T>) + 'static,
    ) {
        self.jobs.set(self.jobs.get() + 1);
        let (tx, rx) = mpsc::channel();
        let service = self.service.clone();
        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(&service)))
                .unwrap_or_else(|_| Err(anyhow::anyhow!("后台任务意外结束")));
            let _ = tx.send(result);
        });
        let weak = Rc::downgrade(self);
        let mut done = Some(done);
        glib::timeout_add_local(Duration::from_millis(40), move || {
            let Some(ui) = weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            let result = match rx.try_recv() {
                Ok(result) => result,
                Err(mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                Err(mpsc::TryRecvError::Disconnected) => Err(anyhow::anyhow!("后台任务意外结束")),
            };
            ui.jobs.set(ui.jobs.get().saturating_sub(1));
            if let Some(done) = done.take() {
                done(&ui, result);
            }
            glib::ControlFlow::Break
        });
    }
    fn button_task<T: Send + 'static>(
        self: &Rc<Self>,
        button: &gtk::Button,
        busy: &str,
        work: impl FnOnce(&Service) -> Result<T> + Send + 'static,
        done: impl FnOnce(&Rc<Self>, Result<T>) + 'static,
    ) {
        let original = button.child();
        let content = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let spinner = gtk::Spinner::new();
        spinner.set_size_request(18, 18);
        spinner.start();
        content.append(&spinner);
        if !button.has_css_class("floating-action") {
            content.append(&label(busy, ""));
        }
        content.set_halign(gtk::Align::Center);
        content.set_valign(gtk::Align::Center);
        button.set_child(Some(&content));
        button.set_sensitive(false);
        let weak_button = button.downgrade();
        self.task_result(work, move |ui, result| {
            spinner.stop();
            if let Some(button) = weak_button.upgrade()
                && button.child().as_ref() == Some(content.upcast_ref())
            {
                button.set_child(original.as_ref());
                button.set_sensitive(true);
            }
            done(ui, result);
        });
    }
    fn saved(self: &Rc<Self>) -> Rc<dyn Fn()> {
        let weak = Rc::downgrade(self);
        let page = self.page.get();
        Rc::new(move || {
            if let Some(ui) = weak.upgrade() {
                ui.notify("已保存");
                ui.refresh(page)
            }
        })
    }
    /// Apply a font size to the window and the pieces whose width is measured
    /// in pixels rather than em, so a live preview stays internally consistent.
    fn apply_font_size(&self, font_size: u32) {
        self.typography.apply(font_size);
        let width = sidebar_width(font_size);
        self.split.set_min_sidebar_width(width);
        self.split.set_max_sidebar_width(width);
    }

    /// Resize notifications are frequent. Keep the latest size in memory while
    /// dragging and persist it only once the user has paused.
    fn observe_window_size(self: &Rc<Self>) {
        if self.window.is_maximized() || self.window.is_fullscreen() {
            return;
        }
        // A default-size notification can arrive before the compositor has
        // allocated the new surface. Read the actual size after the debounce,
        // rather than caching the previous allocation here.
        let generation = self.window_size_generation.get().wrapping_add(1);
        self.window_size_generation.set(generation);
        let weak = Rc::downgrade(self);
        glib::timeout_add_local_once(Duration::from_millis(350), move || {
            let Some(ui) = weak.upgrade() else { return };
            if ui.window_size_generation.get() != generation
                || ui.window.is_maximized()
                || ui.window.is_fullscreen()
            {
                return;
            }
            let (width, height) = (ui.window.width(), ui.window.height());
            if width <= 0 || height <= 0 {
                return;
            }
            ui.window_size.replace((width, height));
            let _ = ui.service.update(|state| {
                state.settings.width = width;
                state.settings.height = height;
                Ok(())
            });
        });
    }

    /// Persist the size that was actually on screen when closing, so a resize
    /// immediately followed by a close cannot restore the previous geometry.
    fn save_window_size(&self) {
        self.window_size_generation
            .set(self.window_size_generation.get().wrapping_add(1));
        let (width, height) = (self.window.width(), self.window.height());
        if width > 0 && height > 0 && !self.window.is_maximized() && !self.window.is_fullscreen() {
            self.window_size.replace((width, height));
        }
        let (width, height) = *self.window_size.borrow();
        let _ = self.service.update(|state| {
            state.settings.width = width;
            state.settings.height = height;
            Ok(())
        });
    }

    fn show(self: &Rc<Self>, page: Page) {
        // Capture before reading page data. A change committed while building
        // the page must remain pending for the next heartbeat.
        let revision = self.service.subscription_revision();
        if let Some(dialog) = self.settings_prompt.take() {
            dialog.force_close();
        }
        if let Some(panel) = self.settings_panel.borrow().as_ref() {
            // Reset or restore may have committed settings newer than this
            // form's baseline. Revert previews to the persisted appearance.
            let settings = self.service.snapshot().settings;
            panel.discard_preview();
            self.apply_font_size(settings.font_size);
            apply_theme(&settings.theme);
        }
        self.pending_leave.take();
        self.settings_panel.replace(None);
        self.page.set(page);
        self.dashboard.replace(None);
        self.node_panel.replace(None);
        self.body.remove_css_class("settings-page");
        self.body.remove_css_class("home-page");
        self.body.set_spacing(12);
        self.body.set_margin_bottom(18);
        self.scroll.vadjustment().set_value(0.0);
        if let Some(button) = self.home_action.borrow_mut().take() {
            self.floating.remove_overlay(&button);
        }
        if let Some(button) = self.nodes_action.borrow_mut().take() {
            self.floating.remove_overlay(&button);
        }
        if let Some(button) = self.settings_action.borrow_mut().take() {
            self.floating.remove_overlay(&button);
        }
        self.log_buffer.replace(None);
        while let Some(child) = self.body.first_child() {
            self.body.remove(&child)
        }
        // No page heading: the sidebar already names the current page, and a
        // repeated title only costs a row of vertical space. Pages that need
        // actions keep the same row for them alone.
        let heading = gtk::Box::new(gtk::Orientation::Horizontal, 10);
        heading.set_valign(gtk::Align::Center);
        heading.set_hexpand(true);
        self.body.append(&heading);
        match page {
            Page::Home => self.home(),
            Page::Nodes => self.nodes(),
            Page::Subscriptions => self.subscriptions(&heading),
            Page::Rules => self.rules(&heading),
            Page::Connections => self.connections(&heading),
            Page::Logs => self.logs(&heading),
            Page::Settings => self.settings(&heading),
        }
        if matches!(page, Page::Nodes | Page::Subscriptions) {
            self.subscription_revision.set(revision);
        }
        if heading.first_child().is_none() {
            self.body.remove(&heading);
        } else {
            // Actions sit on the right; the freed title space becomes margin.
            heading.set_halign(gtk::Align::Fill);
            let spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
            spacer.set_hexpand(true);
            heading.prepend(&spacer);
        }
    }

    fn finish_settings_prompt(&self, dialog: &adw::AlertDialog) -> bool {
        // AlertDialog closes itself and emits a response for both button
        // clicks and dismissal. Its closed signal can arrive before response.
        self.settings_prompt
            .borrow_mut()
            .take_if(|current| current == dialog)
            .is_some()
    }

    fn navigate(self: &Rc<Self>, page: Page) {
        if page == self.page.get() {
            return;
        }
        let destination = self.clone();
        if self.confirm_discard_settings(move || destination.navigate(page)) {
            self.show(page);
        }
        self.sync_navigation_selection();
    }

    fn sync_navigation_selection(&self) {
        let index = Page::ALL
            .iter()
            .position(|page| *page == self.page.get())
            .expect("current page");
        self.syncing_navigation.set(true);
        self.nav
            .select_row(self.nav.row_at_index(index as i32).as_ref());
        self.syncing_navigation.set(false);
        if let Some(row) = self.nav.row_at_index(index as i32) {
            let bounds = row.allocation();
            let adjustment = self.nav_scroll.vadjustment();
            let top = bounds.y() as f64;
            let bottom = top + bounds.height() as f64;
            if top < adjustment.value() {
                adjustment.set_value(top);
            } else if bottom > adjustment.value() + adjustment.page_size() {
                adjustment.set_value((bottom - adjustment.page_size()).max(0.0));
            }
        }
    }

    /// Return true only when the caller may leave immediately. A save-and-leave
    /// action is kept by the panel until persistence has really succeeded.
    fn confirm_close(self: &Rc<Self>) -> glib::Propagation {
        let window = self.window.clone();
        if self.confirm_discard_settings(move || window.close()) {
            glib::Propagation::Proceed
        } else {
            glib::Propagation::Stop
        }
    }

    fn confirm_discard_settings(self: &Rc<Self>, leave: impl Fn() + 'static) -> bool {
        if self.page.get() != Page::Settings {
            return true;
        }
        let Some(panel) = self.settings_panel.borrow().as_ref().cloned() else {
            return true;
        };
        panel.confirm_leave(self, Rc::new(leave))
    }
    fn rules(self: &Rc<Self>, heading: &gtk::Box) {
        let add = primary("新建规则", "list-add-symbolic");
        heading.append(&add);
        let weak = Rc::downgrade(self);
        add.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                editors::ruleset(
                    &ui.window,
                    ui.service.clone(),
                    RuleSet::default(),
                    ui.saved(),
                )
            }
        });
        let state = self.service.snapshot();
        if state.rulesets.is_empty() {
            self.body
                .append(&empty("view-list-bullet-symbolic", "暂无规则", ""));
            return;
        }
        let list = card(gtk::Orientation::Vertical, 0);
        for item in state.rulesets {
            let action = match item.action.as_str() {
                "proxy" => "代理",
                "reject" => "拦截",
                _ => "直连",
            };
            let meta = if item.is_remote() {
                action.to_owned()
            } else {
                format!("{action} · 本地")
            };
            let row = resource_row("view-list-bullet-symbolic", &item.name, &meta);
            // Trailing controls live in one fixed-width slot so the switch,
            // the "设置" button and the icon buttons line up across rows that
            // have different numbers of actions.
            let trailing = gtk::Box::new(gtk::Orientation::Horizontal, 6);
            trailing.set_valign(gtk::Align::Center);
            trailing.add_css_class("row-actions");
            let enabled = gtk::Switch::new();
            enabled.set_active(item.enabled);
            enabled.set_valign(gtk::Align::Center);
            enabled.update_property(&[gtk::accessible::Property::Label(&format!(
                "启用{}",
                item.name
            ))]);
            let id = item.id.clone();
            let weak = Rc::downgrade(self);
            let syncing = Rc::new(Cell::new(false));
            enabled.connect_state_set(move |switch, enabled| {
                if syncing.get() {
                    return glib::Propagation::Proceed;
                }
                if let Some(ui) = weak.upgrade() {
                    switch.set_sensitive(false);
                    let switch = switch.downgrade();
                    let id = id.clone();
                    let updated_id = id.clone();
                    let syncing = syncing.clone();
                    ui.task_result(
                        move |s| s.apply_ruleset_enabled(&id, enabled),
                        move |ui, result| {
                            if let Some(switch) = switch.upgrade() {
                                syncing.set(true);
                                if let Some(rule) = ui
                                    .service
                                    .snapshot()
                                    .rulesets
                                    .iter()
                                    .find(|rule| rule.id == updated_id)
                                {
                                    switch.set_state(rule.enabled);
                                    switch.set_active(rule.enabled);
                                }
                                syncing.set(false);
                                switch.set_sensitive(true);
                            }
                            if let Err(error) = result {
                                ui.error("设置规则失败", format!("{error:#}"));
                            }
                        },
                    );
                }
                glib::Propagation::Stop
            });
            trailing.append(&enabled);
            let edit = gtk::Button::with_label("设置");
            edit.add_css_class("compact-action");
            let weak = Rc::downgrade(self);
            let id = item.id.clone();
            edit.connect_clicked(move |_| {
                if let Some(ui) = weak.upgrade()
                    && let Some(rules) = ui
                        .service
                        .snapshot()
                        .rulesets
                        .into_iter()
                        .find(|rules| rules.id == id)
                {
                    editors::ruleset(&ui.window, ui.service.clone(), rules, ui.saved())
                }
            });
            trailing.append(&edit);
            if !item.is_remote() {
                let content = icon_button("document-edit-symbolic", "编辑规则内容");
                let weak = Rc::downgrade(self);
                let id = item.id.clone();
                content.connect_clicked(move |_| {
                    if let Some(ui) = weak.upgrade()
                        && let Some(rules) = ui
                            .service
                            .snapshot()
                            .rulesets
                            .into_iter()
                            .find(|rules| rules.id == id)
                    {
                        editors::rule_content(&ui.window, ui.service.clone(), rules, ui.saved())
                    }
                });
                trailing.append(&content);
                if !item.source.is_empty() {
                    let refresh = icon_button("view-refresh-symbolic", "重新读取文件");
                    let weak = Rc::downgrade(self);
                    let id = item.id.clone();
                    refresh.connect_clicked(move |button| {
                        if let Some(ui) = weak.upgrade() {
                            let id = id.clone();
                            ui.button_task(
                                button,
                                "读取中…",
                                move |s| s.update_ruleset(&id),
                                |ui, result| match result {
                                    Ok(()) => {
                                        ui.notify("规则已更新");
                                        ui.refresh(Page::Rules);
                                    }
                                    Err(error) => ui.error("更新失败", format!("{error:#}")),
                                },
                            );
                        }
                    });
                    trailing.append(&refresh);
                }
            }
            trailing.append(&self.delete_button("rulesets", &item.id, &item.name));
            row.append(&trailing);
            list.append(&row);
        }
        self.body.append(&list);
    }

    fn delete_button(self: &Rc<Self>, kind: &str, id: &str, name: &str) -> gtk::Button {
        let button = icon_button("user-trash-symbolic", "删除");
        let weak = Rc::downgrade(self);
        let kind = kind.to_string();
        let id = id.to_string();
        let name = name.to_string();
        button.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                let dialog = alert_dialog(&format!("删除「{name}」？"), "此操作无法撤销。");
                dialog.add_response("cancel", "取消");
                dialog.add_response("delete", "删除");
                dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
                dialog.set_default_response(Some("cancel"));
                dialog.set_close_response("cancel");
                let weak = Rc::downgrade(&ui);
                let kind = kind.clone();
                let id = id.clone();
                dialog.connect_response(Some("delete"), move |_, _| {
                    if let Some(ui) = weak.upgrade() {
                        let kind = kind.clone();
                        let id = id.clone();
                        ui.task_result(
                            move |s| s.delete_resource(&kind, &id),
                            |ui, result| match result {
                                Ok(()) => {
                                    ui.notify("已删除");
                                    ui.show(ui.page.get());
                                }
                                Err(error) => ui.error("删除失败", format!("{error:#}")),
                            },
                        );
                    }
                });
                dialog.present(Some(&ui.window));
            }
        });
        button
    }

    fn connections(self: &Rc<Self>, heading: &gtk::Box) {
        let refresh = icon_button("view-refresh-symbolic", "刷新连接");
        heading.append(&refresh);
        let weak = Rc::downgrade(self);
        refresh.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.refresh(Page::Connections)
            }
        });
        let close = gtk::Button::with_label("关闭全部");
        close.add_css_class("compact-action");
        close.set_sensitive(self.service.status().running);
        heading.append(&close);
        let weak = Rc::downgrade(self);
        close.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.task(
                    "关闭连接",
                    |s| s.close_all_connections(),
                    |ui, _| {
                        ui.notify("所有连接已关闭");
                        ui.refresh(Page::Connections)
                    },
                )
            }
        });
        if !self.service.status().running {
            self.body
                .append(&empty("network-transmit-receive-symbolic", "暂无连接", ""));
            return;
        }
        let search = gtk::SearchEntry::new();
        search.set_placeholder_text(Some("搜索域名或地址"));
        search.add_css_class("search");
        search.set_widget_name("connections-search");
        search.set_key_capture_widget(Some(&self.window));
        // Esc clears an active filter before it closes anything else, and the
        // box keeps focus after a refresh so typing is not interrupted.
        let clear_search = search.clone();
        let escape = gtk::EventControllerKey::new();
        escape.connect_key_pressed(move |_, key, _, _| {
            if key == gtk::gdk::Key::Escape {
                clear_search.set_text("");
                glib::Propagation::Stop
            } else {
                glib::Propagation::Proceed
            }
        });
        search.add_controller(escape);
        self.body.append(&search);
        let area = gtk::Box::new(gtk::Orientation::Vertical, 16);
        self.body.append(&area);
        area.append(&label("正在读取连接…", "muted"));
        self.task(
            "读取连接",
            |s| s.connections(),
            move |ui, value| {
                clear_box(&area);
                let connections = value["connections"].as_array().cloned().unwrap_or_default();
                let list = gtk::Box::new(gtk::Orientation::Vertical, 0);
                area.append(&list);
                ui.fill_connections(&list, &connections, "");
                let weak = Rc::downgrade(ui);
                search.connect_search_changed(move |search| {
                    if let Some(ui) = weak.upgrade() {
                        ui.fill_connections(&list, &connections, &search.text())
                    }
                });
            },
        );
    }
    fn fill_connections(self: &Rc<Self>, list: &gtk::Box, connections: &[Value], filter: &str) {
        clear_box(list);
        list.add_css_class("surface-card");
        let filter = filter.to_lowercase();
        let mut count = 0;
        for item in connections {
            let metadata = &item["metadata"];
            let host = metadata["host"]
                .as_str()
                .filter(|s| !s.is_empty())
                .or_else(|| metadata["destinationIP"].as_str())
                .unwrap_or("未知目标");
            let process = metadata["processPath"]
                .as_str()
                .or_else(|| metadata["process"].as_str())
                .unwrap_or("");
            if !format!("{host} {process} {}", metadata["sourceIP"])
                .to_lowercase()
                .contains(&filter)
            {
                continue;
            }
            count += 1;
            let chain = item["chains"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" → ");
            let protocol = metadata["network"].as_str().unwrap_or("TCP").to_uppercase();
            let subtitle = format!(
                "{protocol} · {chain}{}",
                if process.is_empty() {
                    String::new()
                } else {
                    format!(
                        " · {}",
                        Path::new(process)
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                    )
                }
            );
            let row = resource_row("network-transmit-receive-symbolic", host, &subtitle);
            let traffic = gtk::Box::new(gtk::Orientation::Vertical, 4);
            traffic.append(&label(
                &format!("↓ {}", bytes(item["download"].as_u64().unwrap_or(0))),
                "small",
            ));
            traffic.append(&label(
                &format!("↑ {}", bytes(item["upload"].as_u64().unwrap_or(0))),
                "muted small",
            ));
            row.append(&traffic);
            let close = icon_button("window-close-symbolic", "关闭此连接");
            let id = item["id"].as_str().unwrap_or("").to_string();
            let weak = Rc::downgrade(self);
            close.connect_clicked(move |_| {
                if let Some(ui) = weak.upgrade() {
                    let id = id.clone();
                    ui.task(
                        "关闭连接",
                        move |s| s.close_connection(&id),
                        |ui, _| ui.refresh(Page::Connections),
                    )
                }
            });
            row.append(&close);
            list.append(&row);
        }
        if count == 0 {
            list.remove_css_class("surface-card");
            list.append(&empty(
                "network-transmit-receive-symbolic",
                "没有活跃连接",
                if filter.is_empty() {
                    "启动后，活动连接会显示在这里。"
                } else {
                    "没有找到符合筛选条件的连接。"
                },
            ));
        }
    }

    fn logs(self: &Rc<Self>, heading: &gtk::Box) {
        let copy = icon_button("edit-copy-symbolic", "复制日志");
        heading.append(&copy);
        let weak = Rc::downgrade(self);
        copy.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.window.clipboard().set_text(&ui.service.logs());
                ui.notify("日志已复制")
            }
        });
        let export = icon_button("document-save-symbolic", "导出日志");
        heading.append(&export);
        let weak = Rc::downgrade(self);
        export.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.save_text("AeroBox.log", ui.service.logs())
            }
        });
        let clear = gtk::Button::with_label("清空");
        clear.add_css_class("compact-action");
        heading.append(&clear);
        let weak = Rc::downgrade(self);
        clear.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.service.clear_logs();
                if let Some(buffer) = ui.log_buffer.borrow().as_ref() {
                    buffer.set_text("")
                }
            }
        });
        let logs = self.service.logs();
        let frame = card(gtk::Orientation::Vertical, 0);
        let buffer = gtk::TextBuffer::new(None::<&gtk::TextTagTable>);
        buffer.set_text(&logs);
        let view = gtk::TextView::with_buffer(&buffer);
        view.set_editable(false);
        view.set_cursor_visible(false);
        view.set_monospace(false);
        view.set_wrap_mode(gtk::WrapMode::WordChar);
        view.set_left_margin(18);
        view.set_right_margin(18);
        view.set_top_margin(18);
        view.set_bottom_margin(18);
        view.add_css_class("log-view");
        let scroll = gtk::ScrolledWindow::builder()
            .child(&view)
            .min_content_height(420)
            .vexpand(true)
            .build();
        frame.append(&scroll);
        self.body.append(&frame);
        self.log_buffer.replace(Some(buffer));
    }

    fn refresh(self: &Rc<Self>, page: Page) {
        if self.page.get() == page {
            let dashboard = self.dashboard.borrow().clone();
            if page == Page::Home
                && let Some(dashboard) = dashboard
            {
                dashboard.refresh(self);
                dashboard.tick(self);
            } else {
                self.show(page);
            }
        }
    }
    fn save_text(self: &Rc<Self>, name: &str, text: String) {
        let dialog = gtk::FileDialog::builder()
            .title("保存文件")
            .initial_name(name)
            .build();
        let weak = Rc::downgrade(self);
        dialog.save(
            Some(&self.window),
            None::<&gio::Cancellable>,
            move |result| {
                if let (Ok(file), Some(ui)) = (result, weak.upgrade())
                    && let Some(path) = file.path()
                {
                    ui.task(
                        "保存文件",
                        move |_| model::atomic_write(&path, text.as_bytes(), 0o600),
                        |ui, ()| ui.notify("文件已保存"),
                    )
                }
            },
        );
    }
}

fn alert_dialog(title: &str, body: &str) -> adw::AlertDialog {
    let dialog = adw::AlertDialog::new(None::<&str>, None::<&str>);
    // Keep heading and body constrained independently. AlertDialog's own
    // heading label does not wrap in libadwaita 1.5, so use equivalent labels.
    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    let heading = gtk::Label::builder()
        .label(title)
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .justify(gtk::Justification::Center)
        .halign(gtk::Align::Center)
        .width_chars(20)
        .max_width_chars(36)
        .build();
    heading.add_css_class("title-3");
    content.append(&heading);
    let body = gtk::Label::builder()
        .label(body)
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .justify(gtk::Justification::Center)
        .width_chars(20)
        .max_width_chars(36)
        .build();
    content.append(&body);
    dialog.set_extra_child(Some(&content));
    dialog
}

fn apply_theme(theme: &str) {
    adw::StyleManager::default().set_color_scheme(match theme {
        "light" => adw::ColorScheme::ForceLight,
        "dark" => adw::ColorScheme::ForceDark,
        _ => adw::ColorScheme::Default,
    });
}
/// Depth-first list of every descendant widget, used by the UI checks.
pub(super) fn descendants(root: &impl IsA<gtk::Widget>) -> Vec<gtk::Widget> {
    let mut widgets = vec![];
    let mut child = root.first_child();
    while let Some(widget) = child {
        child = widget.next_sibling();
        widgets.extend(descendants(&widget));
        widgets.push(widget);
    }
    widgets
}

fn label(text: &str, classes: &str) -> gtk::Label {
    let label = gtk::Label::builder().label(text).xalign(0.0).build();
    // The hierarchy is defined in styles/theme.css. Adding libadwaita title or
    // heading classes here as well made sizes fight each other, so plain
    // app-level classes are all this needs.
    for class in classes.split_whitespace() {
        label.add_css_class(class);
    }
    label
}
fn margin(widget: &impl IsA<gtk::Widget>, left: i32, right: i32, top: i32, bottom: i32) {
    widget.set_margin_start(left);
    widget.set_margin_end(right);
    widget.set_margin_top(top);
    widget.set_margin_bottom(bottom);
}
fn card(orientation: gtk::Orientation, spacing: i32) -> gtk::Box {
    let card = gtk::Box::new(orientation, spacing);
    card.add_css_class("surface-card");
    card
}
fn icon_button(icon: &str, tooltip: &str) -> gtk::Button {
    let button = gtk::Button::from_icon_name(icon);
    button.set_tooltip_text(Some(tooltip));
    button.add_css_class("flat");
    button.add_css_class("compact-action");
    button.set_valign(gtk::Align::Center);
    button
}
fn floating_button(icon: &str, title: &str) -> gtk::Button {
    let button = gtk::Button::from_icon_name(icon);
    button.add_css_class("suggested-action");
    button.add_css_class("floating-action");
    button.set_tooltip_text(Some(title));
    button.update_property(&[gtk::accessible::Property::Label(title)]);
    button
}

fn follow_theme(window: &impl IsA<gtk::Window>) {
    let window = window.as_ref();
    let manager = adw::StyleManager::default();
    if manager.is_dark() {
        window.add_css_class("dark");
    }
    let weak = window.downgrade();
    // Disconnect when the dialog closes; repeated imports must not retain callbacks.
    let handler = manager.connect_dark_notify(move |manager| {
        if let Some(window) = weak.upgrade() {
            if manager.is_dark() {
                window.add_css_class("dark");
            } else {
                window.remove_css_class("dark");
            }
        }
    });
    let handler = RefCell::new(Some(handler));
    window.connect_destroy(move |_| {
        if let Some(handler) = handler.borrow_mut().take() {
            manager.disconnect(handler);
        }
    });
}
fn bolt() -> gtk::Image {
    // A real symbolic icon follows foreground colour on the selected blue card.
    gtk::Image::from_icon_name("aerobox-bolt-symbolic")
}

fn primary(title: &str, icon: &str) -> gtk::Button {
    let button = gtk::Button::new();
    button.add_css_class("suggested-action");
    button.add_css_class("primary-action");
    button.set_valign(gtk::Align::Center);
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 7);
    row.append(&gtk::Image::from_icon_name(icon));
    row.append(&label(title, ""));
    button.set_child(Some(&row));
    button
}
fn resource_row(icon: &str, title: &str, subtitle: &str) -> gtk::Box {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    row.add_css_class("resource-row");
    let image = gtk::Image::from_icon_name(icon);
    image.add_css_class("row-icon");
    row.append(&image);
    let text = gtk::Box::new(gtk::Orientation::Vertical, 6);
    text.set_hexpand(true);
    text.set_valign(gtk::Align::Center);
    let title = label(title, "resource-name");
    title.set_ellipsize(gtk::pango::EllipsizeMode::End);
    title.set_width_chars(9);
    text.append(&title);
    let subtitle = label(subtitle, "resource-subtitle");
    subtitle.set_ellipsize(gtk::pango::EllipsizeMode::End);
    if !subtitle.text().is_empty() {
        text.append(&subtitle);
    }
    row.append(&text);
    row
}
fn empty(icon: &str, title: &str, description: &str) -> gtk::Box {
    let root = gtk::Box::new(gtk::Orientation::Vertical, 16);
    margin(&root, 24, 24, 54, 54);
    root.set_halign(gtk::Align::Center);
    let image = gtk::Image::from_icon_name(icon);
    image.add_css_class("empty-icon");
    image.set_halign(gtk::Align::Center);
    root.append(&image);
    let title = label(title, "empty-title");
    title.set_halign(gtk::Align::Center);
    root.append(&title);
    let description = label(description, "empty-description");
    description.set_wrap(true);
    description.set_max_width_chars(48);
    description.set_justify(gtk::Justification::Center);
    description.set_halign(gtk::Align::Center);
    root.append(&description);
    root
}
/// Numeric settings as a plain entry: `AdwSpinRow` always draws stepper
/// buttons, and hiding them is not supported, so a filtered entry is used
/// instead. Non-digits are rejected as they are typed.
fn number_entry(title: &str, value: &str) -> LabeledEntry {
    let field = LabeledEntry::new(title, value);
    field.entry.set_input_purpose(gtk::InputPurpose::Digits);
    field.entry.set_max_length(6);
    // Reject non-digits as they are typed instead of clamping afterwards.
    field.entry.connect_insert_text(|entry, text, _| {
        if !text.chars().all(|c| c.is_ascii_digit()) {
            entry.stop_signal_emission_by_name("insert-text");
        }
    });
    field
}

fn switch_row(title: &str, subtitle: &str, active: bool) -> adw::SwitchRow {
    adw::SwitchRow::builder()
        .title(title)
        .subtitle(subtitle)
        .active(active)
        .build()
}
// The column target matches the compact card widths; the FlowBox keeps its
// rows evenly sized without turning the remaining cards into row fillers.
// Watching the width from a frame-clock tick is the signal this GTK4
// version reliably offers.
// Sidebar width follows the font so the brand and nav labels keep their
/// margins instead of clipping against a fixed track.
fn sidebar_width(font_size: u32) -> f64 {
    // Narrow enough to leave the cards room, but still wide enough for the
    // longest navigation label at the largest supported font size.
    128.0 * (font_size as f64 / 11.0).clamp(0.92, 1.5)
}
fn follow_width(
    grid: &gtk::FlowBox,
    min_card_width: i32,
    spacing: i32,
    max_columns: u32,
    responsive: bool,
) {
    let last_width = std::rc::Rc::new(Cell::new(-1));
    let grid_weak = grid.downgrade();
    grid.add_tick_callback(move |_, _| {
        let Some(grid) = grid_weak.upgrade() else {
            return glib::ControlFlow::Break;
        };
        let width = grid.width();
        if width != last_width.get() {
            last_width.set(width);
            let scale = if responsive {
                grid.pango_context()
                    .font_description()
                    .map(|font| {
                        let points = font.size() as f32 / gtk::pango::SCALE as f32;
                        // Large text needs more room, but not a fully linear
                        // column collapse at every small size increase.
                        (points / 11.0).sqrt().clamp(0.85, 1.4)
                    })
                    .unwrap_or(1.0)
            } else {
                1.0
            };
            let card = (min_card_width as f32 * scale).round() as i32;
            let gap = (spacing as f32 * scale).round() as i32;
            if width > 0 && card > 0 {
                let columns = ((width + gap) / (card + gap)).clamp(1, max_columns as i32);
                if grid.max_children_per_line() != columns as u32 {
                    grid.set_max_children_per_line(columns as u32);
                }
                // Let GTK reduce the column count when the children's measured
                // minima no longer fit. Pinning min=max here makes a two-column
                // grid wider than the window before this callback can run again.
                if grid.min_children_per_line() != 1 {
                    grid.set_min_children_per_line(1);
                }
            }
        }
        glib::ControlFlow::Continue
    });
}
/// Label above a plain entry. `AdwEntryRow` reflows its label into the corner as
/// soon as there is text, which reads as a cramped, shifting layout; a fixed
/// caption plus a placeholder stays put no matter what the field contains.
#[derive(Clone)]
pub(super) struct LabeledEntry {
    pub(super) root: gtk::Box,
    pub(super) entry: gtk::Entry,
}

impl LabeledEntry {
    pub(super) fn new(title: &str, text: &str) -> Self {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 6);
        root.add_css_class("labeled-entry");
        let caption = gtk::Label::builder().label(title).xalign(0.0).build();
        caption.add_css_class("labeled-entry-title");
        let entry = gtk::Entry::builder()
            .placeholder_text(title)
            .text(text)
            .hexpand(true)
            .build();
        entry.add_css_class("labeled-entry-input");
        root.append(&caption);
        root.append(&entry);
        Self { root, entry }
    }
    /// Place a button beside the entry and return the wrapper to append into.
    pub(super) fn with_suffix(&self, widget: &impl IsA<gtk::Widget>) -> gtk::Box {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        self.root.remove(&self.entry);
        self.root.append(&row);
        row.append(&self.entry);
        row.append(widget);
        row
    }
    pub(super) fn text(&self) -> String {
        self.entry.text().to_string()
    }
}
fn clear_box(container: &gtk::Box) {
    while let Some(child) = container.first_child() {
        container.remove(&child)
    }
}
fn duration(seconds: u64) -> String {
    if seconds >= 3600 {
        format!("{}h {:02}m", seconds / 3600, seconds % 3600 / 60)
    } else {
        format!("{:02}:{:02}", seconds / 60, seconds % 60)
    }
}
fn bytes(bytes: u64) -> String {
    let n = bytes as f64;
    if n >= 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} GB", n / 1024.0 / 1024.0 / 1024.0)
    } else if n >= 1024.0 * 1024.0 {
        format!("{:.1} MB", n / 1024.0 / 1024.0)
    } else if n >= 1024.0 {
        format!("{:.1} KB", n / 1024.0)
    } else {
        format!("{bytes} B")
    }
}
