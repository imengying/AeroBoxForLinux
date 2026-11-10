use super::*;
use aerobox_for_linux::subscription;

impl Ui {
    pub(super) fn start_subscription_updates(self: &Rc<Self>) {
        let weak = Rc::downgrade(self);
        glib::timeout_add_local_once(Duration::from_secs(5), move || {
            if let Some(ui) = weak.upgrade() {
                ui.update_due_subscriptions();
            }
        });
        let weak = Rc::downgrade(self);
        glib::timeout_add_local(Duration::from_secs(60), move || {
            let Some(ui) = weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            ui.update_due_subscriptions();
            glib::ControlFlow::Continue
        });
    }

    fn update_due_subscriptions(self: &Rc<Self>) {
        if self.jobs.get() != 0 || self.subscription_update_pending.replace(true) {
            return;
        }
        let service = self.service.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(service.update_due_subscriptions());
        });
        let weak = Rc::downgrade(self);
        glib::timeout_add_local(Duration::from_millis(200), move || {
            let Some(ui) = weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            match rx.try_recv() {
                Err(mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                _ => {
                    ui.subscription_update_pending.set(false);
                    glib::ControlFlow::Break
                }
            }
        });
    }

    pub(super) fn subscriptions(self: &Rc<Self>, heading: &gtk::Box) {
        let add = primary("导入订阅", "list-add-symbolic");
        add.set_widget_name("subscription-import");
        heading.append(&add);
        let weak = Rc::downgrade(self);
        add.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.import_subscription();
            }
        });
        let state = self.service.snapshot();
        if state.subscriptions.is_empty() {
            self.body
                .append(&empty("folder-download-symbolic", "暂无订阅", ""));
            return;
        }
        let update = icon_button("view-refresh-symbolic", "更新全部订阅");
        heading.append(&update);
        let weak = Rc::downgrade(self);
        update.connect_clicked(move |button| {
            if let Some(ui) = weak.upgrade() {
                ui.button_task(
                    button,
                    "更新中…",
                    |s| s.update_all_subscriptions(),
                    |ui, result| {
                        match result {
                            Ok(count) => ui.notify(&format!("已更新 {count} 个订阅")),
                            Err(error) => ui.error("订阅更新失败", format!("{error:#}")),
                        }
                        ui.refresh(Page::Subscriptions);
                    },
                );
            }
        });
        let list = gtk::FlowBox::new();
        list.set_hexpand(true);
        list.set_widget_name("subscriptions-grid");
        list.add_css_class("subscriptions-grid");
        list.set_selection_mode(gtk::SelectionMode::None);
        list.set_activate_on_single_click(true);
        list.set_homogeneous(true);
        list.set_min_children_per_line(1);
        list.set_max_children_per_line(2);
        list.set_column_spacing(16);
        list.set_row_spacing(16);
        list.set_valign(gtk::Align::Start);
        let ids: Vec<_> = state
            .subscriptions
            .iter()
            .map(|sub| sub.id.clone())
            .collect();
        let indicators = Rc::new(RefCell::new(Vec::<(gtk::Stack, gtk::Spinner)>::new()));
        for item in state.subscriptions {
            let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
            content.add_css_class("subscription-card-content");
            let card = gtk::FlowBoxChild::new();
            card.set_widget_name("subscription-card");
            card.add_css_class("subscription-card");
            card.set_focusable(true);
            let selected = item.id == state.settings.active_subscription;
            if selected {
                card.add_css_class("subscription-selected");
            }
            card.update_property(&[gtk::accessible::Property::Label(&item.name)]);
            card.update_state(&[gtk::accessible::State::Selected(Some(selected))]);
            let header = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            header.add_css_class("subscription-card-header");
            let title = label(&item.name, "subscription-name");
            title.set_widget_name("subscription-name");
            title.set_hexpand(true);
            title.set_ellipsize(gtk::pango::EllipsizeMode::End);
            title.set_width_chars(1);
            title.set_max_width_chars(1);
            title.set_tooltip_text(Some(&item.name));
            header.append(&title);
            let indicator = gtk::Stack::new();
            indicator.set_size_request(18, 18);
            indicator.set_valign(gtk::Align::Center);
            let check = gtk::Image::from_icon_name("object-select-symbolic");
            check.add_css_class("selection-check");
            indicator.add_named(&check, Some("chosen"));
            indicator.add_named(
                &gtk::Box::new(gtk::Orientation::Horizontal, 0),
                Some("empty"),
            );
            let spinner = gtk::Spinner::new();
            indicator.add_named(&spinner, Some("busy"));
            indicator.set_visible_child_name(if selected { "chosen" } else { "empty" });
            indicators.borrow_mut().push((indicator.clone(), spinner));
            header.append(&indicator);
            let expiry = if item.expires == 0 {
                "有效期 —".to_owned()
            } else {
                let date = format_timestamp(item.expires, "%Y-%m-%d");
                format!(
                    "{date} {}",
                    if item.expires <= model::now() {
                        "已到期"
                    } else {
                        "到期"
                    }
                )
            };
            let expiration = label(&expiry, "subscription-expiry muted small");
            expiration.set_widget_name("subscription-expiry");
            if item.expires > 0 && item.expires <= model::now() {
                expiration.add_css_class("error");
            }
            header.append(&expiration);
            let menu = gtk::MenuButton::builder()
                .icon_name("view-more-symbolic")
                .tooltip_text("订阅操作")
                .valign(gtk::Align::Center)
                .build();
            menu.set_widget_name("subscription-menu");
            menu.add_css_class("flat");
            menu.add_css_class("card-menu");
            let popover = gtk::Popover::new();
            let actions = gtk::Box::new(gtk::Orientation::Vertical, 4);
            actions.add_css_class("subscription-actions");
            let edit = gtk::Button::with_label("订阅设置");
            edit.add_css_class("flat");
            let weak = Rc::downgrade(self);
            let sub = item.clone();
            let pop = popover.downgrade();
            edit.connect_clicked(move |_| {
                if let Some(pop) = pop.upgrade() {
                    pop.popdown();
                }
                if let Some(ui) = weak.upgrade() {
                    editors::subscription(&ui.window, ui.service.clone(), sub.clone(), ui.saved());
                }
            });
            actions.append(&edit);
            let refresh = gtk::Button::with_label("更新订阅");
            refresh.add_css_class("flat");
            refresh.set_sensitive(!item.source.is_empty());
            let weak = Rc::downgrade(self);
            let id = item.id.clone();
            refresh.connect_clicked(move |button| {
                if let Some(ui) = weak.upgrade() {
                    let id = id.clone();
                    ui.button_task(
                        button,
                        "更新中…",
                        move |s| s.update_subscription(&id),
                        |ui, result| match result {
                            Ok(()) => {
                                ui.notify("订阅已更新");
                                ui.refresh(Page::Subscriptions);
                            }
                            Err(error) => ui.error("订阅更新失败", format!("{error:#}")),
                        },
                    );
                }
            });
            actions.append(&refresh);
            let delete = self.delete_button("subscriptions", &item.id, &item.name);
            delete.set_label("删除订阅");
            delete.add_css_class("error");
            let pop = popover.downgrade();
            delete.connect_clicked(move |_| {
                if let Some(pop) = pop.upgrade() {
                    pop.popdown();
                }
            });
            actions.append(&delete);
            popover.set_child(Some(&actions));
            menu.set_popover(Some(&popover));
            header.append(&menu);
            content.append(&header);
            let used = item.download.saturating_add(item.upload);
            let progress = gtk::ProgressBar::new();
            progress.set_widget_name("subscription-progress");
            progress.add_css_class("subscription-progress");
            progress.set_fraction(if item.total > 0 {
                (used as f64 / item.total as f64).min(1.0)
            } else {
                0.0
            });
            progress.set_margin_top(18);
            progress.set_margin_bottom(16);
            content.append(&progress);
            let footer = gtk::Box::new(gtk::Orientation::Horizontal, 12);
            let usage = label(
                &if item.total > 0 {
                    format!("{} / {}", bytes(used), bytes(item.total))
                } else {
                    "— / —".into()
                },
                "subscription-usage",
            );
            usage.set_widget_name("subscription-usage");
            usage.set_hexpand(true);
            usage.set_ellipsize(gtk::pango::EllipsizeMode::End);
            usage.set_tooltip_text(Some(&if item.total > 0 {
                format!("已用 {}，总量 {}", bytes(used), bytes(item.total))
            } else {
                "订阅未提供流量信息".into()
            }));
            footer.append(&usage);
            let updated = label(&updated(item.updated), "subscription-updated muted small");
            updated.set_widget_name("subscription-updated");
            updated.set_tooltip_text(
                (item.updated > 0)
                    .then(|| format_timestamp(item.updated, "%Y-%m-%d %H:%M"))
                    .as_deref(),
            );
            footer.append(&updated);
            content.append(&footer);
            card.set_child(Some(&content));
            list.insert(&card, -1);
        }

        let weak = Rc::downgrade(self);
        let busy = Rc::new(Cell::new(false));
        list.connect_child_activated(move |list, row| {
            if busy.replace(true) {
                return;
            }
            let (Some(ui), Some(id)) = (weak.upgrade(), ids.get(row.index() as usize)) else {
                busy.set(false);
                return;
            };
            let id = id.clone();
            let (indicator, spinner) = indicators.borrow()[row.index() as usize].clone();
            indicator.set_visible_child_name("busy");
            spinner.start();
            list.set_sensitive(false);
            let list = list.downgrade();
            let busy = busy.clone();
            ui.task_result(
                move |s| s.select_subscription(&id),
                move |ui, result| {
                    busy.set(false);
                    spinner.stop();
                    if let Some(list) = list.upgrade() {
                        list.set_sensitive(true);
                    }
                    ui.subscription_revision
                        .set(ui.service.subscription_revision());
                    ui.refresh(Page::Subscriptions);
                    if let Err(error) = result {
                        ui.error("切换订阅失败", format!("{error:#}"));
                    }
                },
            );
        });
        self.body.append(&list);
    }

    pub(super) fn import_subscription(self: &Rc<Self>) {
        let window = adw::Window::builder()
            .title("导入订阅")
            .transient_for(&self.window)
            .modal(true)
            .default_width(600)
            .default_height(640)
            .build();
        if let Some(app) = self.window.application() {
            window.set_application(Some(&app));
        }
        let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
        root.add_css_class("editor-root");
        let header = adw::HeaderBar::new();
        let import = primary("导入", "document-save-symbolic");
        import.set_widget_name("subscription-import-save");
        header.pack_end(&import);
        root.append(&header);
        let form = gtk::Box::new(gtk::Orientation::Vertical, 18);
        form.set_margin_start(24);
        form.set_margin_end(24);
        form.set_margin_top(24);
        form.set_margin_bottom(24);
        let sources = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        let paste = gtk::Button::with_label("从剪贴板导入");
        let file = gtk::Button::with_label("从文件导入");
        sources.append(&paste);
        sources.append(&file);
        form.append(&sources);
        let name = adw::EntryRow::builder().title("名称（可选）").build();
        let group = adw::PreferencesGroup::new();
        group.add(&name);
        form.append(&group);
        let source_title = gtk::Label::new(Some("订阅链接或节点内容"));
        source_title.set_xalign(0.0);
        form.append(&source_title);
        let source = gtk::TextView::builder()
            .wrap_mode(gtk::WrapMode::WordChar)
            .top_margin(12)
            .bottom_margin(12)
            .left_margin(12)
            .right_margin(12)
            .build();
        source.set_widget_name("subscription-import-source");
        let scroll = gtk::ScrolledWindow::builder()
            .child(&source)
            .min_content_height(110)
            .vexpand(true)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .build();
        scroll.add_css_class("card");
        form.append(&scroll);
        let auto_update = switch_row("自动更新", "", true);
        let interval = adw::SpinRow::with_range(1.0, 168.0, 1.0);
        interval.set_title("更新间隔（小时）");
        interval.set_value(24.0);
        let interval_toggle = interval.clone();
        auto_update
            .connect_active_notify(move |row| interval_toggle.set_sensitive(row.is_active()));
        let updates = adw::PreferencesGroup::new();
        updates.add(&auto_update);
        updates.add(&interval);
        form.append(&updates);
        let error = gtk::Label::builder()
            .wrap(true)
            .xalign(0.0)
            .visible(false)
            .selectable(true)
            .build();
        error.set_widget_name("subscription-import-error");
        error.add_css_class("error");
        form.append(&error);
        let form_scroll = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .child(&form)
            .build();
        root.append(&form_scroll);
        window.set_content(Some(&root));
        let buffer = source.buffer();
        let clipboard = window.clipboard();
        let paste_error = error.clone();
        paste.connect_clicked(move |_| {
            let buffer = buffer.clone();
            let error = paste_error.clone();
            clipboard.read_text_async(None::<&gio::Cancellable>, move |result| match result {
                Ok(Some(text)) => {
                    buffer.set_text(&text);
                    error.set_visible(false);
                }
                _ => {
                    error.set_text("剪贴板没有可导入的文本");
                    error.set_visible(true);
                }
            });
        });
        let weak_window = window.downgrade();
        let weak = Rc::downgrade(self);
        let file_source = source.buffer();
        let file_name = name.clone();
        let file_error = error.clone();
        file.connect_clicked(move |button| {
            let (Some(parent), Some(ui)) = (weak_window.upgrade(), weak.upgrade()) else {
                return;
            };
            let buffer = file_source.clone();
            let name = file_name.clone();
            let error = file_error.clone();
            let button = button.clone();
            let weak = Rc::downgrade(&ui);
            gtk::FileDialog::builder()
                .title("导入订阅文件")
                .build()
                .open(Some(&parent), None::<&gio::Cancellable>, move |result| {
                    let (Ok(file), Some(ui)) = (result, weak.upgrade()) else {
                        return;
                    };
                    let Some(path) = file.path() else {
                        return;
                    };
                    let filename = path
                        .file_stem()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned();
                    ui.button_task(
                        &button,
                        "读取中…",
                        move |_| {
                            anyhow::ensure!(
                                std::fs::metadata(&path)?.len() <= 8 * 1024 * 1024,
                                "文件超过 8 MiB"
                            );
                            Ok((
                                std::fs::read_to_string(path).context("无法读取订阅文件")?,
                                filename,
                            ))
                        },
                        move |_, result| match result {
                            Ok((text, filename)) => {
                                buffer.set_text(&text);
                                if name.text().is_empty() {
                                    name.set_text(&filename);
                                }
                                error.set_visible(false);
                            }
                            Err(e) => {
                                error.set_text(&format!("{e:#}"));
                                error.set_visible(true);
                            }
                        },
                    );
                });
        });
        let weak = Rc::downgrade(self);
        let weak_window = window.downgrade();
        let busy = Rc::new(Cell::new(false));
        let close_guard = busy.clone();
        window.connect_close_request(move |_| {
            if close_guard.get() {
                glib::Propagation::Stop
            } else {
                glib::Propagation::Proceed
            }
        });
        import.connect_clicked(move |button| {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let buffer = source.buffer();
            let input = buffer
                .text(&buffer.start_iter(), &buffer.end_iter(), false)
                .to_string();
            let name = name.text().trim().to_owned();
            let auto_update = auto_update.is_active();
            let interval = interval.value() as u32;
            let window = weak_window.clone();
            let error = error.clone();
            let busy = busy.clone();
            error.set_visible(false);
            busy.set(true);
            ui.button_task(
                button,
                "导入中…",
                move |s| {
                    let mut sub = subscription::import_input(&input)?;
                    if !name.is_empty() {
                        sub.name = name;
                    }
                    sub.auto_update = auto_update && !sub.source.is_empty();
                    sub.update_interval_hours = interval;
                    s.import_subscription(sub)
                },
                move |ui, result| {
                    busy.set(false);
                    match result {
                        Ok(()) => {
                            if let Some(window) = window.upgrade() {
                                window.close();
                            }
                            ui.notify("订阅已导入");
                            ui.refresh(Page::Subscriptions);
                        }
                        Err(e) => {
                            error.set_text(&format!("{e:#}"));
                            error.set_visible(true);
                        }
                    }
                },
            );
        });
        window.present();
    }
}

fn format_timestamp(timestamp: u64, pattern: &str) -> String {
    i64::try_from(timestamp)
        .ok()
        .and_then(|value| glib::DateTime::from_unix_local(value).ok())
        .and_then(|date| date.format(pattern).ok())
        .map(|date| date.to_string())
        .unwrap_or_else(|| "—".into())
}

pub(super) fn smoke_selection(ui: &Rc<Ui>, active: usize, click: Option<usize>) -> Result<()> {
    use anyhow::ensure;
    fn descendants(root: &impl IsA<gtk::Widget>) -> Vec<gtk::Widget> {
        let mut result = vec![];
        let mut child = root.first_child();
        while let Some(widget) = child {
            child = widget.next_sibling();
            result.extend(descendants(&widget));
            result.push(widget);
        }
        result
    }
    ensure!(ui.jobs.get() == 0, "订阅选用未完成");
    let widgets = descendants(&ui.body);
    ensure!(
        !widgets
            .iter()
            .filter_map(|w| w.downcast_ref::<gtk::Button>())
            .any(|b| matches!(b.label().as_deref(), Some("使用" | "已使用"))),
        "仍然需要使用按钮"
    );
    let list = widgets
        .iter()
        .find(|w| w.widget_name() == "subscriptions-grid")
        .context("缺少订阅列表")?
        .clone()
        .downcast::<gtk::FlowBox>()
        .unwrap();
    let state = ui.service.snapshot();
    ensure!(
        state.settings.active_subscription == state.subscriptions[active].id,
        "点击没有选用订阅"
    );
    for (index, _) in state.subscriptions.iter().enumerate() {
        let row = list.child_at_index(index as i32).unwrap();
        ensure!(
            row.has_css_class("subscription-selected") == (index == active),
            "订阅高亮不准确"
        );
        if row.width() > 0 && list.width() > 0 {
            let bounds = row.compute_bounds(&list).context("订阅卡片没有位置")?;
            ensure!(
                bounds.x() >= 0.0 && bounds.x() + bounds.width() <= list.width() as f32 + 1.0,
                "订阅卡片超出页面"
            );
            let parts = descendants(&row);
            let get = |name: &str| -> Result<gtk::graphene::Rect> {
                parts
                    .iter()
                    .find(|w| w.widget_name() == name)
                    .context("订阅卡片缺少信息")?
                    .compute_bounds(&row)
                    .context("订阅卡片信息没有位置")
            };
            let name = get("subscription-name")?;
            let expiry = get("subscription-expiry")?;
            let progress = get("subscription-progress")?;
            let usage = get("subscription-usage")?;
            let updated = get("subscription-updated")?;
            ensure!(
                name.y() + name.height() <= progress.y()
                    && expiry.y() + expiry.height() <= progress.y(),
                "进度条没有位于名称和有效期下方"
            );
            ensure!(
                usage.y() >= progress.y() + progress.height()
                    && updated.y() >= progress.y() + progress.height(),
                "流量和更新时间没有位于进度条下方"
            );
            ensure!(
                usage.x() + usage.width() <= updated.x(),
                "流量和更新时间重叠"
            );
            if index == 1 {
                let first = list
                    .child_at_index(0)
                    .unwrap()
                    .compute_bounds(&list)
                    .unwrap();
                if ui.window.width() >= 1100 {
                    ensure!(
                        (bounds.y() - first.y()).abs() < 1.0 && bounds.x() > first.x(),
                        "常规窗口没有一行两个订阅"
                    );
                } else if ui.window.width() <= 620 {
                    ensure!(
                        bounds.y() >= first.y() + first.height(),
                        "窄窗口没有改为单列订阅"
                    );
                }
            }
        }
    }
    if let Some(index) = click {
        let row = list.child_at_index(index as i32).unwrap();
        list.emit_by_name::<()>("child-activated", &[&row]);
        ensure!(
            list.child_at_index(active as i32)
                .unwrap()
                .has_css_class("subscription-selected"),
            "选用成功前丢失原高亮"
        );
    }
    Ok(())
}

pub(super) fn smoke_menu(ui: &Rc<Ui>, open: bool) -> Result<()> {
    fn find(widget: &gtk::Widget) -> Option<gtk::MenuButton> {
        if widget.widget_name() == "subscription-menu" {
            return widget.clone().downcast().ok();
        }
        let mut child = widget.first_child();
        while let Some(widget) = child {
            child = widget.next_sibling();
            if let Some(menu) = find(&widget) {
                return Some(menu);
            }
        }
        None
    }
    let menu = find(ui.body.upcast_ref()).context("缺少订阅操作菜单")?;
    if open {
        menu.popup();
    } else {
        menu.popdown();
    }
    Ok(())
}

pub(super) fn smoke_import(ui: &Rc<Ui>, step: u32) -> Result<()> {
    use anyhow::ensure;
    fn descendants(root: &impl IsA<gtk::Widget>) -> Vec<gtk::Widget> {
        let mut widgets = vec![];
        let mut next = root.first_child();
        while let Some(child) = next {
            next = child.next_sibling();
            widgets.extend(descendants(&child));
            widgets.push(child);
        }
        widgets
    }
    if step == 3 {
        ensure!(ui.jobs.get() == 0, "订阅导入未完成");
        let state = ui.service.snapshot();
        let sub = state
            .subscriptions
            .iter()
            .find(|s| s.name == "导入检查")
            .context("导入订阅没有保存")?;
        ensure!(
            sub.source.is_empty() && !sub.auto_update && sub.nodes.len() == 1,
            "本地导入状态无效"
        );
        ensure!(
            state.settings.active_subscription == sub.id,
            "导入的订阅没有选用"
        );
        return Ok(());
    }
    let window = ui
        .window
        .application()
        .context("缺少应用")?
        .windows()
        .into_iter()
        .find(|w| w.title().as_deref() == Some("导入订阅"))
        .context("导入窗口不存在")?;
    let widgets = descendants(&window);
    let source = widgets
        .iter()
        .find(|w| w.widget_name() == "subscription-import-source")
        .context("缺少导入文本框")?
        .clone()
        .downcast::<gtk::TextView>()
        .unwrap();
    let save = widgets
        .iter()
        .find(|w| w.widget_name() == "subscription-import-save")
        .context("缺少导入按钮")?
        .clone()
        .downcast::<gtk::Button>()
        .unwrap();
    if step == 1 {
        source.buffer().set_text("invalid input");
    } else {
        ensure!(
            ui.jobs.get() == 0 && save.is_sensitive(),
            "失败后导入按钮没有恢复"
        );
        ensure!(
            widgets
                .iter()
                .find(|w| w.widget_name() == "subscription-import-error")
                .is_some_and(|w| w.is_visible()),
            "导入失败没有显示错误"
        );
        ensure!(
            !ui.service
                .snapshot()
                .subscriptions
                .iter()
                .any(|s| s.name == "导入检查"),
            "失败导入留下了空订阅"
        );
        source.buffer().set_text(
            r#"[{"type":"socks","tag":"导入检查","server":"127.0.0.1","server_port":1080}]"#,
        );
    }
    save.emit_clicked();
    ensure!(!save.is_sensitive(), "导入期间按钮没有禁用");
    Ok(())
}
