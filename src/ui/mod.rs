mod core;
mod editors;
mod home;
mod settings;
mod subscriptions;
mod typography;

use adw::prelude::*;
use aerobox_for_linux::{
    engine::Service,
    model::{self, Profile, RuleSet, Subscription},
    platform,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Page {
    Home,
    Nodes,
    Profiles,
    Subscriptions,
    Rules,
    Connections,
    Logs,
    Settings,
}
impl Page {
    const ALL: [Self; 8] = [
        Self::Home,
        Self::Nodes,
        Self::Subscriptions,
        Self::Profiles,
        Self::Rules,
        Self::Connections,
        Self::Logs,
        Self::Settings,
    ];
    fn title(self) -> &'static str {
        match self {
            Self::Home => "首页",
            Self::Nodes => "节点",
            Self::Profiles => "配置",
            Self::Subscriptions => "订阅",
            Self::Rules => "规则集",
            Self::Connections => "连接",
            Self::Logs => "日志",
            Self::Settings => "设置",
        }
    }
    fn icon(self) -> &'static str {
        match self {
            Self::Home => "go-home-symbolic",
            Self::Nodes => "network-wireless-symbolic",
            Self::Profiles => "document-properties-symbolic",
            Self::Subscriptions => "folder-download-symbolic",
            Self::Rules => "view-list-bullet-symbolic",
            Self::Connections => "network-transmit-receive-symbolic",
            Self::Logs => "utilities-terminal-symbolic",
            Self::Settings => "preferences-system-symbolic",
        }
    }
}

pub fn run(service: Arc<Service>, smoke: Option<PathBuf>) -> glib::ExitCode {
    if smoke.is_some()
        && let Err(e) = seed_smoke(&service)
    {
        eprintln!("smoke fixture: {e:#}");
        return glib::ExitCode::FAILURE;
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
    app.connect_activate(move |app| {
        if let Some(window) = app.active_window() {
            window.present();
            return;
        }
        let provider = gtk::CssProvider::new();
        provider.load_from_data(include_str!("../../resources/style.css"));
        gtk::style_context_add_provider_for_display(
            &gtk::gdk::Display::default().expect("Wayland display"),
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
        let ui = Ui::new(app, activate_service.clone());
        ui.window.present();
        if let Some(path) = smoke.clone() {
            smoke_sequence(ui.clone(), path, activate_failed.clone());
        } else {
            ui.start_subscription_updates();
            let settings = ui.service.snapshot().settings;
            if settings.auto_start || settings.update_subscriptions_on_start {
                ui.task(
                    "启动",
                    move |s| {
                        let result = (|| {
                            let state = s.snapshot();
                            let needs_nodes = state
                                .profiles
                                .iter()
                                .find(|p| p.id == settings.active_profile)
                                .is_some_and(|p| {
                                    p.subscriptions.iter().any(|id| {
                                        state
                                            .subscriptions
                                            .iter()
                                            .any(|sub| &sub.id == id && sub.nodes.is_empty())
                                    })
                                });
                            let update_first = settings.auto_start
                                && settings.update_subscriptions_on_start
                                && needs_nodes;
                            if update_first {
                                s.update_all_subscriptions()?;
                            }
                            let start = if settings.auto_start {
                                s.start()
                            } else {
                                Ok(())
                            };
                            let update = if settings.update_subscriptions_on_start && !update_first
                            {
                                s.update_all_subscriptions()
                            } else {
                                Ok(0)
                            };
                            start?;
                            update?;
                            Ok(())
                        })();
                        Ok(result)
                    },
                    |ui, result: Result<()>| {
                        ui.refresh(Page::Home);
                        if let Err(e) = result {
                            ui.error("启动失败", format!("{e:#}"));
                        }
                    },
                );
            }
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
    if failed.get() {
        glib::ExitCode::FAILURE
    } else {
        result
    }
}

struct Ui {
    typography: typography::Typography,
    window: adw::ApplicationWindow,
    service: Arc<Service>,
    toast: adw::ToastOverlay,
    body: gtk::Box,
    scroll: gtk::ScrolledWindow,
    floating: gtk::Overlay,
    home_action: RefCell<Option<gtk::Button>>,
    nav: gtk::ListBox,
    page: Cell<Page>,
    split: adw::OverlaySplitView,
    jobs: Cell<usize>,
    last_pid: Cell<Option<u32>>,
    subscription_revision: Cell<u64>,
    subscription_update_pending: Cell<bool>,
    dashboard: RefCell<Option<Rc<home::Dashboard>>>,
    core: RefCell<Option<Rc<core::CorePanel>>>,
    log_buffer: RefCell<Option<gtk::TextBuffer>>,
    node_group: RefCell<String>,
}

impl Ui {
    fn new(app: &adw::Application, service: Arc<Service>) -> Rc<Self> {
        let settings = service.snapshot().settings;
        apply_theme(&settings.theme);
        let typography = typography::Typography::new(settings.text_scale, settings.crisp_text);
        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("AeroBox")
            .default_width(settings.width.max(700))
            .default_height(settings.height.max(600))
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
        sidebar.append(&side_header);
        let brand = gtk::Box::new(gtk::Orientation::Horizontal, 11);
        margin(&brand, 24, 24, 2, 28);
        brand.update_property(&[gtk::accessible::Property::Label("AeroBox")]);
        let data = glib::Bytes::from_static(include_bytes!(
            "../../resources/io.github.imengying.AeroBoxForLinux.png"
        ));
        let texture = gtk::gdk::Texture::from_bytes(&data).expect("embedded PNG icon");
        let mark = gtk::Image::from_paintable(Some(&texture));
        mark.set_pixel_size(42);
        let name = label("AeroBox", "brand");
        name.set_valign(gtk::Align::Center);
        brand.append(&mark);
        brand.append(&name);
        sidebar.append(&brand);
        let nav = gtk::ListBox::new();
        nav.add_css_class("nav-list");
        nav.set_selection_mode(gtk::SelectionMode::Single);
        margin(&nav, 14, 14, 0, 0);
        for page in Page::ALL {
            let row = gtk::ListBoxRow::new();
            let item = gtk::Box::new(gtk::Orientation::Horizontal, 13);
            item.add_css_class("nav-item");
            margin(&item, 15, 12, 0, 0);
            let image = gtk::Image::from_icon_name(page.icon());
            image.set_pixel_size(18);
            item.append(&image);
            item.append(&label(page.title(), ""));
            row.set_child(Some(&item));
            nav.append(&row);
        }
        nav.select_row(nav.row_at_index(0).as_ref());
        sidebar.append(&nav);
        let split = adw::OverlaySplitView::new();
        split.set_sidebar(Some(&sidebar));
        split.set_min_sidebar_width(216.0);
        split.set_max_sidebar_width(216.0);
        split.set_sidebar_width_fraction(0.2);
        let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let header = adw::HeaderBar::new();
        header.add_css_class("transparent-header");
        header.set_title_widget(Some(&gtk::Box::new(gtk::Orientation::Horizontal, 0)));
        let sidebar_button = icon_button("sidebar-show-symbolic", "显示导航");
        sidebar_button.set_visible(false);
        let weak = split.downgrade();
        sidebar_button.connect_clicked(move |_| {
            if let Some(split) = weak.upgrade() {
                split.set_show_sidebar(!split.shows_sidebar())
            }
        });
        header.pack_start(&sidebar_button);
        let weak_button = sidebar_button.downgrade();
        split.connect_collapsed_notify(move |split| {
            if let Some(button) = weak_button.upgrade() {
                button.set_visible(split.is_collapsed())
            }
        });
        content.append(&header);
        let body = gtk::Box::new(gtk::Orientation::Vertical, 24);
        body.add_css_class("page-content");
        margin(&body, 30, 30, 18, 32);
        let clamp = adw::Clamp::builder()
            .maximum_size(1030)
            .tightening_threshold(850)
            .child(&body)
            .build();
        let scroll = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
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
        let breakpoint = adw::Breakpoint::new(
            adw::BreakpointCondition::parse("max-width: 860sp").expect("breakpoint"),
        );
        breakpoint.add_setter(&split, "collapsed", Some(&true.to_value()));
        window.add_breakpoint(breakpoint);
        let ui = Rc::new(Self {
            typography,
            window,
            service,
            toast,
            body,
            scroll,
            floating,
            home_action: RefCell::new(None),
            nav,
            page: Cell::new(Page::Home),
            split,
            jobs: Cell::new(0),
            last_pid: Cell::new(None),
            subscription_revision: Cell::new(0),
            subscription_update_pending: Cell::new(false),
            dashboard: RefCell::new(None),
            core: RefCell::new(None),
            log_buffer: RefCell::new(None),
            node_group: RefCell::new(String::new()),
        });
        let weak = Rc::downgrade(&ui);
        ui.nav.connect_row_selected(move |_, row| {
            if let (Some(ui), Some(row)) = (weak.upgrade(), row) {
                ui.show(Page::ALL[row.index() as usize]);
                if ui.split.is_collapsed() {
                    ui.split.set_show_sidebar(false)
                }
            }
        });
        ui.refresh(Page::Home);
        let weak = Rc::downgrade(&ui);
        glib::timeout_add_local(Duration::from_secs(1), move || {
            let Some(ui) = weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            let status = ui.service.status();
            if ui.last_pid.replace(status.pid) != status.pid {
                if ui.page.get() == Page::Home {
                    ui.refresh(Page::Home)
                } else if ui.page.get() == Page::Profiles {
                    ui.refresh(Page::Profiles)
                }
            }
            let revision = ui.service.subscription_revision();
            if ui.jobs.get() == 0
                && ui.subscription_revision.replace(revision) != revision
                && matches!(
                    ui.page.get(),
                    Page::Subscriptions | Page::Nodes | Page::Profiles
                )
            {
                ui.refresh(ui.page.get());
            }
            if let Some(dashboard) = ui.dashboard.borrow().as_ref() {
                dashboard.tick(&ui);
            }
            if let Some(core) = ui.core.borrow().as_ref() {
                core.tick(&ui);
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
        self.toast.add_toast(adw::Toast::new(message));
    }
    fn error(&self, title: &str, error: impl std::fmt::Display) {
        let dialog =
            adw::MessageDialog::new(Some(&self.window), Some(title), Some(&error.to_string()));
        dialog.add_response("close", "知道了");
        dialog.set_default_response(Some("close"));
        dialog.present();
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
        content.append(&label(busy, ""));
        button.set_child(Some(&content));
        button.set_sensitive(false);
        let weak_button = button.downgrade();
        self.task_result(work, move |ui, result| {
            spinner.stop();
            if let Some(button) = weak_button.upgrade() {
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
    fn show(self: &Rc<Self>, page: Page) {
        if self.page.get() == Page::Settings && page != Page::Settings {
            let settings = self.service.snapshot().settings;
            self.typography
                .apply(settings.text_scale, settings.crisp_text);
        }
        self.page.set(page);
        self.dashboard.replace(None);
        self.core.replace(None);
        self.body.remove_css_class("settings-page");
        self.body.remove_css_class("home-page");
        self.body.set_spacing(24);
        self.body.set_margin_bottom(32);
        self.scroll.vadjustment().set_value(0.0);
        self.scroll.set_margin_bottom(0);
        if let Some(button) = self.home_action.borrow_mut().take() {
            self.floating.remove_overlay(&button);
        }
        self.log_buffer.replace(None);
        while let Some(child) = self.body.first_child() {
            self.body.remove(&child)
        }
        let heading = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        let titles = gtk::Box::new(gtk::Orientation::Vertical, 7);
        titles.set_hexpand(true);
        titles.append(&label(page.title(), "page-title"));
        heading.append(&titles);
        self.body.append(&heading);
        match page {
            Page::Home => self.home(),
            Page::Nodes => self.nodes(&heading),
            Page::Profiles => self.profiles(&heading),
            Page::Subscriptions => self.subscriptions(&heading),
            Page::Rules => self.rules(&heading),
            Page::Connections => self.connections(&heading),
            Page::Logs => self.logs(&heading),
            Page::Settings => self.settings(&heading),
        }
    }

    fn navigate(self: &Rc<Self>, page: Page) {
        let index = Page::ALL.iter().position(|p| *p == page).expect("page");
        self.nav
            .select_row(self.nav.row_at_index(index as i32).as_ref());
    }
    fn preset_button(self: &Rc<Self>, heading: &gtk::Box) {
        let button = gtk::Button::with_label("添加内置");
        button.add_css_class("compact-action");
        button.set_valign(gtk::Align::Center);
        let weak = Rc::downgrade(self);
        button.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                match ui
                    .service
                    .update(|s| model::add_builtin_resources(s).map(|_| ()))
                {
                    Ok(()) => {
                        ui.notify("内置配置与规则已就绪");
                        ui.refresh(ui.page.get());
                    }
                    Err(e) => ui.error("添加失败", e),
                }
            }
        });
        heading.append(&button);
    }
    fn profiles(self: &Rc<Self>, heading: &gtk::Box) {
        self.preset_button(heading);
        let add = primary("新建配置", "list-add-symbolic");
        heading.append(&add);
        let weak = Rc::downgrade(self);
        add.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                editors::profile(
                    &ui.window,
                    ui.service.clone(),
                    Profile::new("新配置"),
                    ui.saved(),
                )
            }
        });
        let import = gtk::Button::with_label("导入 JSON");
        import.add_css_class("compact-action");
        import.set_valign(gtk::Align::Center);
        heading.append(&import);
        let weak = Rc::downgrade(self);
        import.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.import_profile()
            }
        });
        let state = self.service.snapshot();
        if state.profiles.is_empty() {
            self.body.append(&empty(
                "document-new-symbolic",
                "还没有配置",
                "新建一份配置，或者导入现有的 sing-box JSON 文件。",
            ));
            return;
        }
        let list = card(gtk::Orientation::Vertical, 0);
        for p in state.profiles {
            let subtitle = format!(
                "{} 个订阅 · {} 个规则集",
                p.subscriptions.len(),
                p.rulesets.len()
            );
            let row = resource_row("document-properties-symbolic", &p.name, &subtitle);
            if p.id == state.settings.active_profile {
                row.append(&pill("当前配置", "active"));
                if self.service.status().running {
                    let reload = icon_button("view-refresh-symbolic", "重新加载此配置");
                    let weak = Rc::downgrade(self);
                    reload.connect_clicked(move |button| {
                        if let Some(ui) = weak.upgrade() {
                            if ui.jobs.get() > 0 {
                                return;
                            }
                            ui.button_task(
                                button,
                                "重载中…",
                                |s| s.reload(),
                                |ui, result| match result {
                                    Ok(()) => {
                                        ui.notify("配置已重新加载");
                                        ui.refresh(Page::Profiles);
                                    }
                                    Err(e) => ui.error("重载失败", format!("{e:#}")),
                                },
                            );
                        }
                    });
                    row.append(&reload);
                }
            } else {
                let select = icon_button("object-select-symbolic", "设为当前配置");
                select.set_sensitive(!self.service.status().running);
                let weak = Rc::downgrade(self);
                let id = p.id.clone();
                select.connect_clicked(move |_| {
                    if let Some(ui) = weak.upgrade() {
                        let id = id.clone();
                        match ui.service.update(|s| {
                            s.settings.active_profile = id;
                            Ok(())
                        }) {
                            Ok(()) => ui.refresh(Page::Profiles),
                            Err(e) => ui.error("切换配置失败", e),
                        }
                    }
                });
                row.append(&select);
            }
            let edit = gtk::Button::with_label("编辑");
            edit.add_css_class("compact-action");
            let weak = Rc::downgrade(self);
            let item = p.clone();
            edit.connect_clicked(move |_| {
                if let Some(ui) = weak.upgrade() {
                    editors::profile(&ui.window, ui.service.clone(), item.clone(), ui.saved())
                }
            });
            row.append(&edit);
            let preview = icon_button("document-open-symbolic", "预览生成的配置");
            let weak = Rc::downgrade(self);
            let id = p.id.clone();
            preview.connect_clicked(move |_| {
                if let Some(ui) = weak.upgrade() {
                    let id = id.clone();
                    ui.task(
                        "生成配置",
                        move |s| s.generate(&id),
                        |ui, value| {
                            editors::code(
                                &ui.window,
                                "运行配置预览",
                                &model::pretty(&value),
                                "json",
                                None,
                            )
                        },
                    )
                }
            });
            row.append(&preview);
            let check = icon_button("security-high-symbolic", "校验配置");
            let weak = Rc::downgrade(self);
            let id = p.id.clone();
            check.connect_clicked(move |_| {
                if let Some(ui) = weak.upgrade() {
                    let id = id.clone();
                    ui.task(
                        "校验配置",
                        move |s| s.check_profile(&id),
                        |ui, ()| ui.notify("配置校验通过"),
                    )
                }
            });
            row.append(&check);
            let export = icon_button("document-save-symbolic", "导出配置");
            let weak = Rc::downgrade(self);
            let item = p.clone();
            export.connect_clicked(move |_| {
                if let Some(ui) = weak.upgrade() {
                    ui.save_text(&format!("{}.json", item.name), model::pretty(&item.config))
                }
            });
            row.append(&export);
            let copy = icon_button("edit-copy-symbolic", "复制配置");
            let weak = Rc::downgrade(self);
            let item = p.clone();
            copy.connect_clicked(move |_| {
                if let Some(ui) = weak.upgrade() {
                    let mut copy = item.clone();
                    copy.id = model::id();
                    copy.name = format!("{} 副本", copy.name);
                    if let Err(e) = ui.service.update(|s| {
                        s.profiles.push(copy);
                        Ok(())
                    }) {
                        ui.error("复制配置失败", e)
                    } else {
                        ui.refresh(Page::Profiles)
                    }
                }
            });
            row.append(&copy);
            row.append(&self.delete_button("profiles", &p.id, &p.name));
            list.append(&row);
        }
        self.body.append(&list);
    }

    fn rules(self: &Rc<Self>, heading: &gtk::Box) {
        self.preset_button(heading);
        let add = primary("新建规则集", "list-add-symbolic");
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
            self.body.append(&empty(
                "view-list-bullet-symbolic",
                "让流量各行其道",
                "新建本地规则集，或者添加远程 JSON / SRS 规则来源。",
            ));
            return;
        }
        let list = card(gtk::Orientation::Vertical, 0);
        for item in state.rulesets {
            let meta = format!(
                "{} · {}",
                if item.source.is_empty() {
                    "本地规则"
                } else {
                    "远程规则"
                },
                updated(item.updated)
            );
            let row = resource_row("view-list-bullet-symbolic", &item.name, &meta);
            row.append(&pill(if item.binary { "SRS" } else { "JSON" }, ""));
            let edit = gtk::Button::with_label("编辑");
            edit.add_css_class("compact-action");
            let weak = Rc::downgrade(self);
            let rules = item.clone();
            edit.connect_clicked(move |_| {
                if let Some(ui) = weak.upgrade() {
                    editors::ruleset(&ui.window, ui.service.clone(), rules.clone(), ui.saved())
                }
            });
            row.append(&edit);
            let content = icon_button("document-edit-symbolic", "编辑规则内容");
            let weak = Rc::downgrade(self);
            let rules = item.clone();
            content.connect_clicked(move |_| {
                if let Some(ui) = weak.upgrade() {
                    editors::rule_content(&ui.window, ui.service.clone(), rules.clone(), ui.saved())
                }
            });
            row.append(&content);
            let refresh = icon_button("view-refresh-symbolic", "更新规则集");
            refresh.set_sensitive(!item.source.is_empty());
            let weak = Rc::downgrade(self);
            let id = item.id.clone();
            refresh.connect_clicked(move |_| {
                if let Some(ui) = weak.upgrade() {
                    let id = id.clone();
                    ui.task(
                        "更新规则集",
                        move |s| s.update_ruleset(&id),
                        |ui, ()| {
                            ui.notify("规则集已更新");
                            ui.refresh(Page::Rules)
                        },
                    )
                }
            });
            row.append(&refresh);
            row.append(&self.delete_button("rulesets", &item.id, &item.name));
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
                if kind == "profiles"
                    && ui.service.status().running
                    && ui.service.snapshot().settings.active_profile == id
                {
                    ui.notify("请先停止正在使用此配置的内核");
                    return;
                }
                let dialog = adw::MessageDialog::new(
                    Some(&ui.window),
                    Some(&format!("删除「{name}」？")),
                    Some("此操作无法撤销，相关配置中的引用也会一并移除。"),
                );
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
                        match ui.service.update(|s| model::remove_resource(s, &kind, &id)) {
                            Ok(()) => {
                                ui.notify("已删除");
                                ui.show(ui.page.get())
                            }
                            Err(e) => ui.error("删除失败", e),
                        }
                    }
                });
                dialog.present();
            }
        });
        button
    }

    fn nodes(self: &Rc<Self>, heading: &gtk::Box) {
        let refresh = icon_button("view-refresh-symbolic", "刷新节点");
        heading.append(&refresh);
        let weak = Rc::downgrade(self);
        refresh.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.refresh(Page::Nodes)
            }
        });
        let area = gtk::Box::new(gtk::Orientation::Vertical, 16);
        self.body.append(&area);
        if self.service.status().running {
            area.append(&label("正在读取代理组…", "muted"));
            self.task(
                "读取节点",
                |s| s.api("GET", "/proxies", None),
                move |ui, value| {
                    clear_box(&area);
                    ui.proxy_groups(&area, value)
                },
            );
        } else {
            let state = self.service.snapshot();
            let count = state
                .subscriptions
                .iter()
                .map(|s| s.nodes.len())
                .sum::<usize>();
            if count == 0 {
                area.append(&empty(
                    "network-wireless-symbolic",
                    "从一个订阅开始",
                    "添加订阅并关联到配置，启动内核后即可切换节点与测速。",
                ));
                return;
            }
            let search = gtk::SearchEntry::new();
            search.set_placeholder_text(Some("搜索节点名称或协议"));
            search.add_css_class("search");
            area.append(&search);
            let nodes = gtk::Box::new(gtk::Orientation::Vertical, 16);
            area.append(&nodes);
            let data: Vec<_> = state
                .subscriptions
                .iter()
                .map(|s| (s.name.clone(), s.nodes.clone()))
                .collect();
            fill_saved_nodes(&nodes, &data, "");
            search.connect_search_changed(move |search| {
                fill_saved_nodes(&nodes, &data, &search.text())
            });
        }
    }
    fn proxy_groups(self: &Rc<Self>, area: &gtk::Box, value: Value) {
        let Some(proxies) = value["proxies"].as_object() else {
            area.append(&empty(
                "network-wireless-symbolic",
                "没有可选择的代理组",
                "在配置中添加 selector 或 urltest 出站后重试。",
            ));
            return;
        };
        let mut groups: Vec<_> = proxies
            .iter()
            .filter(|(_, p)| p["all"].is_array())
            .map(|(name, _)| name.clone())
            .collect();
        groups.sort();
        if groups.is_empty() {
            area.append(&empty(
                "network-wireless-symbolic",
                "没有可选择的代理组",
                "当前配置没有 selector 或 urltest 代理组。",
            ));
            return;
        }
        let controls = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        controls.append(&label("代理组", "muted"));
        let names: Vec<&str> = groups.iter().map(String::as_str).collect();
        let dropdown = gtk::DropDown::from_strings(&names);
        if let Some(index) = groups.iter().position(|g| g == &*self.node_group.borrow()) {
            dropdown.set_selected(index as u32)
        }
        controls.append(&dropdown);
        let search = gtk::SearchEntry::new();
        search.set_placeholder_text(Some("搜索节点"));
        search.set_hexpand(true);
        search.add_css_class("search");
        controls.append(&search);
        let test = gtk::Button::with_label("全部测速");
        test.add_css_class("compact-action");
        controls.append(&test);
        area.append(&controls);
        let nodes = gtk::Box::new(gtk::Orientation::Vertical, 12);
        area.append(&nodes);
        let weak = Rc::downgrade(self);
        let data = Rc::new(value);
        let groups = Rc::new(groups);
        let render: Rc<dyn Fn()> = Rc::new({
            let dropdown = dropdown.clone();
            let search = search.clone();
            let groups = groups.clone();
            let data = data.clone();
            move || {
                if let Some(ui) = weak.upgrade()
                    && let Some(group) = groups.get(dropdown.selected() as usize)
                {
                    ui.node_group.replace(group.clone());
                    ui.fill_proxy_nodes(&nodes, &data, group, &search.text())
                }
            }
        });
        render();
        let r = render.clone();
        dropdown.connect_selected_notify(move |_| r());
        let r = render;
        search.connect_search_changed(move |_| r());
        let weak = Rc::downgrade(self);
        test.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                let Some(group) = groups.get(dropdown.selected() as usize) else {
                    return;
                };
                let names: Vec<String> = data["proxies"][group]["all"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect();
                ui.task(
                    "节点测速",
                    move |s| {
                        let settings = s.snapshot().settings;
                        let mut success = 0;
                        for name in names {
                            if s.api(
                                "GET",
                                &delay_path(&name, &settings.test_url, settings.test_timeout),
                                None,
                            )
                            .is_ok()
                            {
                                success += 1;
                            }
                        }
                        Ok(success)
                    },
                    |ui, success| {
                        ui.notify(&format!("已完成测速，{success} 个节点可用"));
                        ui.refresh(Page::Nodes)
                    },
                );
            }
        });
        let mode_row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
        margin(&mode_row, 0, 0, 10, 0);
        mode_row.append(&label("路由模式", "muted"));
        let modes = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        modes.add_css_class("linked");
        modes.set_sensitive(false);
        let mut choices: Vec<(&str, gtk::ToggleButton)> = Vec::new();
        for (text, mode) in [("规则", "rule"), ("全局", "global"), ("直连", "direct")] {
            let button = gtk::ToggleButton::with_label(text);
            if let Some((_, first)) = choices.first() {
                button.set_group(Some(first));
            }
            modes.append(&button);
            choices.push((mode, button));
        }
        for (mode, button) in &choices {
            let weak = Rc::downgrade(self);
            let mode = mode.to_string();
            let controls = modes.downgrade();
            button.connect_clicked(move |button| {
                if let (Some(ui), Some(controls)) = (weak.upgrade(), controls.upgrade()) {
                    controls.set_sensitive(false);
                    let mode = mode.clone();
                    let controls = controls.clone();
                    ui.button_task(
                        button.upcast_ref::<gtk::Button>(),
                        "切换中…",
                        move |s| s.set_routing_mode(&mode),
                        move |ui, result| {
                            controls.set_sensitive(true);
                            match result {
                                Ok(_) => {
                                    ui.notify("路由模式已切换");
                                }
                                Err(e) => {
                                    ui.refresh(Page::Nodes);
                                    ui.error("切换路由模式失败", e);
                                }
                            }
                        },
                    )
                }
            });
        }
        mode_row.append(&modes);
        area.append(&mode_row);
        self.task(
            "读取路由模式",
            |s| s.runtime_mode(),
            move |_, mode| {
                for (name, button) in choices {
                    button.set_active(name == mode);
                }
                modes.set_sensitive(true);
            },
        );
    }
    fn fill_proxy_nodes(self: &Rc<Self>, area: &gtk::Box, data: &Value, group: &str, filter: &str) {
        clear_box(area);
        let group_data = &data["proxies"][group];
        let current = group_data["now"].as_str().unwrap_or("");
        let manual = group_data["type"] == "Selector";
        if !manual {
            area.append(&label("自动选择", "muted"));
        }
        let filter = filter.to_lowercase();
        let flow = gtk::FlowBox::new();
        flow.set_selection_mode(gtk::SelectionMode::None);
        flow.set_column_spacing(12);
        flow.set_row_spacing(12);
        flow.set_homogeneous(true);
        flow.set_min_children_per_line(1);
        flow.set_max_children_per_line(3);
        let mut count = 0;
        for name in group_data["all"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if !name.to_lowercase().contains(&filter) {
                continue;
            }
            count += 1;
            let selected = name == current;
            let node = &data["proxies"][name];
            let item = card(gtk::Orientation::Vertical, 8);
            item.add_css_class("node-card");
            if selected {
                item.add_css_class("selected")
            }
            let choose = gtk::Button::new();
            choose.add_css_class("flat");
            choose.set_tooltip_text(Some("选择此节点"));
            let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            let title = label(name, "resource-name");
            title.set_hexpand(true);
            title.set_ellipsize(gtk::pango::EllipsizeMode::End);
            row.append(&title);
            let check = gtk::Image::from_icon_name(if selected {
                "object-select-symbolic"
            } else {
                "radio-symbolic"
            });
            check.add_css_class("muted");
            row.append(&check);
            if manual {
                choose.set_child(Some(&row));
            }
            let weak = Rc::downgrade(self);
            let name_owned = name.to_string();
            let group = group.to_string();
            choose.connect_clicked(move |_| {
                if let Some(ui) = weak.upgrade() {
                    let name = name_owned.clone();
                    let group = group.clone();
                    ui.task(
                        "选择节点",
                        move |s| s.select_outbound(&group, &name),
                        |ui, _| ui.refresh(Page::Nodes),
                    )
                }
            });
            if manual {
                item.append(&choose);
            } else {
                item.append(&row);
            }
            let meta = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            let protocol = label(node["type"].as_str().unwrap_or("代理"), "resource-subtitle");
            protocol.set_hexpand(true);
            meta.append(&protocol);
            let delay = node["history"]
                .as_array()
                .and_then(|h| h.last())
                .and_then(|h| h["delay"].as_u64());
            let text = delay
                .map(|v| {
                    if v == 0 {
                        "超时".to_string()
                    } else {
                        format!("{v} ms")
                    }
                })
                .unwrap_or_else(|| "测速".into());
            let test = gtk::Button::with_label(&text);
            test.add_css_class("flat");
            test.add_css_class("small");
            let weak = Rc::downgrade(self);
            let name = name.to_string();
            test.connect_clicked(move |button| {
                if let Some(ui) = weak.upgrade() {
                    let name = name.clone();
                    let weak_button = button.downgrade();
                    button.set_label("测试中…");
                    ui.task(
                        "节点测速",
                        move |s| {
                            let settings = s.snapshot().settings;
                            Ok(s.api(
                                "GET",
                                &delay_path(&name, &settings.test_url, settings.test_timeout),
                                None,
                            ))
                        },
                        move |_, result| {
                            if let Some(button) = weak_button.upgrade() {
                                match result {
                                    Ok(value) => button.set_label(&format!(
                                        "{} ms",
                                        value["delay"].as_u64().unwrap_or(0)
                                    )),
                                    Err(e) => {
                                        button.set_label("重试");
                                        button.set_tooltip_text(Some(&format!("{e:#}")))
                                    }
                                }
                            }
                        },
                    );
                }
            });
            meta.append(&test);
            item.append(&meta);
            flow.insert(&item, -1);
        }
        if count == 0 {
            area.append(&empty(
                "edit-find-symbolic",
                "没有匹配的节点",
                "试试其他名称。",
            ))
        } else {
            area.append(&flow)
        }
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
                    |s| s.api("DELETE", "/connections", None),
                    |ui, _| {
                        ui.notify("所有连接已关闭");
                        ui.refresh(Page::Connections)
                    },
                )
            }
        });
        if !self.service.status().running {
            self.body.append(&empty(
                "network-transmit-receive-symbolic",
                "连接将在这里出现",
                "启动内核后，你可以查看流量去向与活跃连接。",
            ));
            return;
        }
        let search = gtk::SearchEntry::new();
        search.set_placeholder_text(Some("搜索域名、地址或进程"));
        search.add_css_class("search");
        self.body.append(&search);
        let area = gtk::Box::new(gtk::Orientation::Vertical, 16);
        self.body.append(&area);
        area.append(&label("正在读取连接…", "muted"));
        self.task(
            "读取连接",
            |s| s.api("GET", "/connections", None),
            move |ui, value| {
                clear_box(&area);
                let metrics = gtk::Box::new(gtk::Orientation::Horizontal, 16);
                metrics.set_homogeneous(true);
                let connections = value["connections"].as_array().cloned().unwrap_or_default();
                metrics.append(&metric(
                    "go-up-symbolic",
                    "累计上传",
                    &bytes(value["uploadTotal"].as_u64().unwrap_or(0)),
                    "本次内核运行期间",
                ));
                metrics.append(&metric(
                    "go-down-symbolic",
                    "累计下载",
                    &bytes(value["downloadTotal"].as_u64().unwrap_or(0)),
                    "本次内核运行期间",
                ));
                metrics.append(&metric(
                    "network-workgroup-symbolic",
                    "活跃连接",
                    &connections.len().to_string(),
                    "点击刷新获取最新状态",
                ));
                area.append(&metrics);
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
                        move |s| s.api("DELETE", &format!("/connections/{}", urlpart(&id)), None),
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
                    "网络请求经过内核时会显示在这里。"
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
        view.set_monospace(true);
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

    fn import_profile(self: &Rc<Self>) {
        let dialog = gtk::FileDialog::builder()
            .title("导入 sing-box 配置")
            .build();
        let filters = gio::ListStore::new::<gtk::FileFilter>();
        let filter = gtk::FileFilter::new();
        filter.set_name(Some("JSON 配置"));
        filter.add_pattern("*.json");
        filters.append(&filter);
        dialog.set_filters(Some(&filters));
        let weak = Rc::downgrade(self);
        dialog.open(
            Some(&self.window),
            None::<&gio::Cancellable>,
            move |result| {
                if let (Ok(file), Some(ui)) = (result, weak.upgrade()) {
                    let Some(path) = file.path() else { return };
                    ui.task(
                        "导入配置",
                        move |_| {
                            let config: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
                            anyhow::ensure!(config.is_object(), "配置必须是 JSON 对象");
                            let mut profile = Profile::new(
                                path.file_stem()
                                    .and_then(|s| s.to_str())
                                    .unwrap_or("导入的配置"),
                            );
                            profile.config = config;
                            Ok(profile)
                        },
                        |ui, profile| {
                            editors::profile(&ui.window, ui.service.clone(), profile, ui.saved())
                        },
                    )
                }
            },
        );
    }
    fn refresh(self: &Rc<Self>, page: Page) {
        if self.page.get() == page {
            self.show(page)
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

fn apply_theme(theme: &str) {
    adw::StyleManager::default().set_color_scheme(match theme {
        "light" => adw::ColorScheme::ForceLight,
        "dark" => adw::ColorScheme::ForceDark,
        _ => adw::ColorScheme::Default,
    });
}
fn label(text: &str, classes: &str) -> gtk::Label {
    let label = gtk::Label::builder().label(text).xalign(0.0).build();
    for class in classes.split_whitespace() {
        label.add_css_class(class);
        match class {
            "page-title" | "brand" => label.add_css_class("title-2"),
            "section-title" | "resource-name" => label.add_css_class("heading"),
            "empty-title" => label.add_css_class("title-3"),
            _ => {}
        }
    }
    label
}
fn margin(widget: &impl IsA<gtk::Widget>, left: i32, right: i32, top: i32, bottom: i32) {
    widget.set_margin_start(left);
    widget.set_margin_end(right);
    widget.set_margin_top(top);
    widget.set_margin_bottom(bottom);
}
fn margin_inner(widget: &impl IsA<gtk::Widget>, _: i32) {
    widget.add_css_class("padded-card");
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
fn pill(text: &str, class: &str) -> gtk::Label {
    let label = label(text, "pill");
    label.set_valign(gtk::Align::Center);
    if !class.is_empty() {
        label.add_css_class(class);
        match class {
            "page-title" | "brand" => label.add_css_class("title-2"),
            "section-title" | "resource-name" => label.add_css_class("heading"),
            "empty-title" => label.add_css_class("title-3"),
            _ => {}
        }
    }
    label
}
fn metric(icon: &str, title: &str, value: &str, subtitle: &str) -> gtk::Box {
    let card = card(gtk::Orientation::Vertical, 10);
    margin_inner(&card, 20);
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    row.append(&label(title, "muted small"));
    let icon = gtk::Image::from_icon_name(icon);
    icon.add_css_class("metric-icon");
    icon.set_hexpand(true);
    icon.set_halign(gtk::Align::End);
    row.append(&icon);
    card.append(&row);
    card.append(&label(value, "metric-value"));
    card.append(&label(subtitle, "resource-subtitle"));
    card
}
fn resource_row(icon: &str, title: &str, subtitle: &str) -> gtk::Box {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    row.add_css_class("resource-row");
    let image = gtk::Image::from_icon_name(icon);
    image.set_pixel_size(20);
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
    image.set_pixel_size(34);
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
fn switch_row(title: &str, subtitle: &str, active: bool) -> adw::SwitchRow {
    adw::SwitchRow::builder()
        .title(title)
        .subtitle(subtitle)
        .active(active)
        .build()
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
fn updated(time: u64) -> String {
    if time == 0 {
        "尚未更新".into()
    } else {
        let age = model::now().saturating_sub(time);
        if age < 60 {
            "刚刚更新".into()
        } else if age < 3600 {
            format!("{} 分钟前更新", age / 60)
        } else if age < 86400 {
            format!("{} 小时前更新", age / 3600)
        } else {
            format!("{} 天前更新", age / 86400)
        }
    }
}
fn urlpart(text: &str) -> String {
    percent_encoding::utf8_percent_encode(text, percent_encoding::NON_ALPHANUMERIC).to_string()
}
fn delay_path(name: &str, url: &str, timeout: u32) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("url", url)
        .append_pair("timeout", &timeout.to_string())
        .finish();
    format!("/proxies/{}/delay?{query}", urlpart(name))
}
fn fill_saved_nodes(area: &gtk::Box, data: &[(String, Vec<Value>)], filter: &str) {
    clear_box(area);
    let filter = filter.to_lowercase();
    for (subscription, nodes) in data {
        let matching: Vec<_> = nodes
            .iter()
            .filter(|node| {
                format!("{} {}", node["tag"], node["type"])
                    .to_lowercase()
                    .contains(&filter)
            })
            .collect();
        if matching.is_empty() {
            continue;
        }
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        row.append(&label(subscription, "section-title"));
        row.append(&pill(&format!("{} 个节点", matching.len()), ""));
        area.append(&row);
        let flow = gtk::FlowBox::new();
        flow.set_selection_mode(gtk::SelectionMode::None);
        flow.set_homogeneous(true);
        flow.set_min_children_per_line(1);
        flow.set_max_children_per_line(3);
        flow.set_column_spacing(12);
        flow.set_row_spacing(12);
        for node in matching {
            let item = card(gtk::Orientation::Vertical, 9);
            item.add_css_class("node-card");
            let name = label(
                node["tag"].as_str().unwrap_or("未命名节点"),
                "resource-name",
            );
            name.set_ellipsize(gtk::pango::EllipsizeMode::End);
            item.append(&name);
            let row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
            let protocol = label(
                &node["type"].as_str().unwrap_or("代理").to_uppercase(),
                "resource-subtitle",
            );
            protocol.set_hexpand(true);
            row.append(&protocol);
            row.append(&label("未连接", "muted small"));
            item.append(&row);
            flow.insert(&item, -1);
        }
        area.append(&flow);
    }
    if area.first_child().is_none() {
        area.append(&empty(
            "edit-find-symbolic",
            "没有匹配的节点",
            "试试其他名称或协议。",
        ));
    }
}

fn seed_smoke(service: &Service) -> Result<()> {
    service.update(|state| {
        state.settings.theme="light".into();state.settings.width=1180;state.settings.height=800;state.settings.auto_detect_ip=false;
        let subscription=Subscription {name:"日常连接".into(),nodes:vec![
            json!({"type":"shadowsocks","tag":"香港 · 01","server":"hk.example.invalid","server_port":443,"method":"aes-128-gcm","password":"smoke-fixture"}),
            json!({"type":"trojan","tag":"日本 · 01","server":"jp.example.invalid","server_port":443,"password":"smoke-fixture","tls":{"enabled":true}}),
            json!({"type":"hysteria2","tag":"新加坡 · 01","server":"sg.example.invalid","server_port":443,"password":"smoke-fixture","tls":{"enabled":true}}),
            json!({"type":"shadowsocks","tag":"美国 · 01","server":"us.example.invalid","server_port":443,"method":"aes-128-gcm","password":"smoke-fixture"}),
            json!({"type":"trojan","tag":"德国 · 01","server":"de.example.invalid","server_port":443,"password":"smoke-fixture","tls":{"enabled":true}}),
            json!({"type":"socks","tag":"本地备用","server":"127.0.0.1","server_port":1080})],updated:model::now()-1200,total:200*1024*1024*1024,download:28*1024*1024*1024,..Subscription::default()};
        let rules=RuleSet{name:"工作服务".into(),content:json!({"version":3,"rules":[{"domain_suffix":["example.com","example.org"]}]}),updated:model::now(),..RuleSet::default()};
        let mut primary=Profile::new("日常上网");primary.subscriptions.push(subscription.id.clone());primary.rulesets.push(rules.id.clone());
        let mut second=Profile::new("工作网络");second.subscriptions.push(subscription.id.clone());
        state.settings.active_profile=primary.id.clone();state.profiles=vec![primary,second];state.subscriptions=vec![subscription];state.rulesets=vec![rules];Ok(())
    })
}

fn screenshot(window: &impl IsA<gtk::Window>, path: &Path) -> Result<()> {
    let window = window.as_ref();
    let width = window.width();
    let height = window.height();
    anyhow::ensure!(width > 0 && height > 0, "窗口尚未分配尺寸");
    let paintable = gtk::WidgetPaintable::new(Some(window));
    let snapshot = gtk::Snapshot::new();
    paintable.snapshot(&snapshot, width as f64, height as f64);
    let node = snapshot.to_node().context("窗口没有渲染内容")?;
    let renderer = window.renderer().context("Wayland 渲染器不可用")?;
    let texture = renderer.render_texture(
        &node,
        Some(&gtk::graphene::Rect::new(
            0.0,
            0.0,
            width as f32,
            height as f32,
        )),
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?
    }
    texture.save_to_png(path)?;
    anyhow::ensure!(std::fs::metadata(path)?.len() > 4000, "截图内容不足");
    Ok(())
}

fn smoke_sequence(ui: Rc<Ui>, path: PathBuf, failed: Rc<Cell<bool>>) {
    let step = Cell::new(0);
    let floating_y = Cell::new(None::<f32>);
    let font_size = Cell::new(None);
    let parent = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let app = ui.window.application().expect("application");
    let guard_app = app.clone();
    let guard_failed = failed.clone();
    glib::timeout_add_local_once(Duration::from_secs(30), move || {
        guard_failed.set(true);
        eprintln!("Wayland smoke: timed out");
        guard_app.quit();
    });
    glib::timeout_add_local(Duration::from_millis(850), move || {
        let current = step.get();
        step.set(current + 1);
        let capture = match current {
            0 => screenshot(&ui.window, &path),
            1 => screenshot(&ui.window, &parent.join("profiles.png")),
            2 => screenshot(&ui.window, &parent.join("nodes.png")),
            3 => screenshot(&ui.window, &parent.join("subscriptions.png")),
            4 => screenshot(&ui.window, &parent.join("rules.png")),
            5 => screenshot(&ui.window, &parent.join("home-dark.png")),
            6 => screenshot(&ui.window, &parent.join("home-narrow.png")),
            7 => screenshot(&ui.window, &parent.join("home-compact.png")),
            8 => screenshot(&ui.window, &parent.join("home-scrolled.png")),
            9 => app
                .active_window()
                .context("配置编辑器没有打开")
                .and_then(|w| screenshot(&w, &parent.join("profile-editor.png"))),
            10 => screenshot(&ui.window, &parent.join("settings.png")),
            11 => screenshot(&ui.window, &parent.join("settings-tun.png")),
            12 => app
                .active_window()
                .context("订阅导入未打开")
                .and_then(|w| screenshot(&w, &parent.join("subscription-import.png"))),
            15 => screenshot(&ui.window, &parent.join("core-settings.png")),
            _ => Ok(()),
        }
        .and_then(|()| {
            if current == 0 {
                let scale = std::env::var("AEROBOX_TEST_SCALE")
                    .ok()
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(1);
                anyhow::ensure!(
                    ui.window.scale_factor() == scale,
                    "显示缩放没有按测试设置生效"
                );
            }
            if current == 7 || current == 8 {
                let button = ui.home_action.borrow();
                let bounds = button
                    .as_ref()
                    .context("首页启动按钮不存在")?
                    .compute_bounds(&ui.floating)
                    .context("启动按钮尚未分配位置")?;
                let height = ui.floating.height() as f32;
                anyhow::ensure!(
                    bounds.x() > ui.floating.width() as f32 - bounds.width() - 56.0
                        && bounds.x() + bounds.width() <= ui.floating.width() as f32
                        && bounds.y() > height - 110.0
                        && bounds.y() + bounds.height() <= height,
                    "启动按钮没有固定在内容区右下角"
                );
                if let Some(previous) = floating_y.get() {
                    anyhow::ensure!(
                        (bounds.y() - previous).abs() < 1.0,
                        "滚动页面移动了悬浮启动按钮"
                    );
                }
                floating_y.set(Some(bounds.y()));
            }
            if current == 1 {
                anyhow::ensure!(ui.home_action.borrow().is_none(), "启动按钮泄漏到配置页");
            }
            Ok(())
        });
        if let Err(e) = capture {
            // The first HiDPI frame can arrive after activation. Wait for that
            // frame; the overall timeout still catches a window that never draws.
            if current == 0 && e.to_string() == "窗口没有渲染内容" {
                step.set(0);
                return glib::ControlFlow::Continue;
            }
            eprintln!("Wayland smoke screenshot {current}: {e:#}");
            failed.set(true);
            app.quit();
            return glib::ControlFlow::Break;
        }
        match current {
            0 => ui.navigate(Page::Profiles),
            1 => ui.navigate(Page::Nodes),
            2 => ui.navigate(Page::Subscriptions),
            3 => ui.navigate(Page::Rules),
            4 => {
                ui.navigate(Page::Home);
                apply_theme("dark");
            }
            5 => {
                apply_theme("light");
                ui.window.set_default_size(790, 800);
            }
            6 => {
                ui.window.set_default_size(700, 600);
            }
            7 => {
                let adjustment = ui.scroll.vadjustment();
                adjustment.set_value(adjustment.upper());
            }
            8 => {
                ui.window.set_default_size(1180, 800);
                ui.navigate(Page::Profiles);
                let profile = ui.service.snapshot().profiles[0].clone();
                editors::profile(&ui.window, ui.service.clone(), profile, ui.saved());
            }
            9 => {
                if let Err(e) = editors::smoke_profile(&ui.window, ui.service.clone()) {
                    eprintln!("Wayland smoke editor: {e:#}");
                    failed.set(true);
                    app.quit();
                    return glib::ControlFlow::Break;
                }
                if let Some(editor) = app.active_window()
                    && editor != ui.window.clone().upcast::<gtk::Window>()
                {
                    editor.close()
                }
                ui.navigate(Page::Settings);
            }
            10 => {
                font_size.set(
                    ui.window
                        .pango_context()
                        .font_description()
                        .map(|font| font.size()),
                );
                if let Err(e) = settings::smoke_settings(&ui, false) {
                    eprintln!("Wayland smoke settings: {e:#}");
                    failed.set(true);
                    app.quit();
                    return glib::ControlFlow::Break;
                }
            }
            11 => {
                if let Err(e) = settings::smoke_settings(&ui, true) {
                    eprintln!("Wayland smoke settings: {e:#}");
                    failed.set(true);
                    app.quit();
                    return glib::ControlFlow::Break;
                }
                let larger = ui
                    .window
                    .pango_context()
                    .font_description()
                    .map(|font| font.size());
                if !matches!((font_size.get(), larger), (Some(before), Some(after)) if after > before)
                {
                    eprintln!("Wayland smoke: text scale did not change rendered font size");
                    failed.set(true);
                    app.quit();
                    return glib::ControlFlow::Break;
                }
                ui.navigate(Page::Subscriptions);
                ui.import_subscription();
            }
            12 | 13 => {
                if let Err(e) = subscriptions::smoke_import(&ui, current - 11) {
                    eprintln!("Wayland smoke import: {e:#}");
                    failed.set(true);
                    app.quit();
                    return glib::ControlFlow::Break;
                }
            }
            14 => {
                if let Err(e) = subscriptions::smoke_import(&ui, 3) {
                    eprintln!("Wayland smoke import: {e:#}");
                    failed.set(true);
                    app.quit();
                    return glib::ControlFlow::Break;
                }
                ui.navigate(Page::Settings);
                fn select_core(widget: &gtk::Widget) {
                    if let Some(stack) = widget.downcast_ref::<gtk::Stack>()
                        && stack.widget_name() == "settings-sections"
                    {
                        stack.set_visible_child_name("core");
                    }
                    let mut child = widget.first_child();
                    while let Some(widget) = child {
                        child = widget.next_sibling();
                        select_core(&widget);
                    }
                }
                select_core(ui.body.upcast_ref());
            }
            15 => {
                let clipboard = ui.window.clipboard();
                clipboard.set_text("AeroBox Wayland 剪贴板测试");
                let failed = failed.clone();
                let app = app.clone();
                clipboard.read_text_async(None::<&gio::Cancellable>,move |result|{if !matches!(result,Ok(Some(ref text))if text=="AeroBox Wayland 剪贴板测试"){failed.set(true);eprintln!("Wayland smoke: clipboard roundtrip failed")}else{println!("Wayland smoke: home, theme, narrow window, collections, editor, settings, subscription import and clipboard passed")}app.quit();});
                return glib::ControlFlow::Break;
            }
            _ => {
                app.quit();
                return glib::ControlFlow::Break;
            }
        }
        glib::ControlFlow::Continue
    });
}
