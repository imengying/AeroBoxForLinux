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
        let list = gtk::ListBox::new();
        list.set_widget_name("subscriptions-list");
        list.add_css_class("subscriptions-list");
        list.set_selection_mode(gtk::SelectionMode::None);
        list.set_activate_on_single_click(true);
        let ids: Vec<_> = state
            .subscriptions
            .iter()
            .map(|sub| sub.id.clone())
            .collect();
        let indicators = Rc::new(RefCell::new(Vec::<(gtk::Stack, gtk::Spinner)>::new()));
        for item in state.subscriptions {
            let card = gtk::Box::new(gtk::Orientation::Vertical, 10);
            let card_row = gtk::ListBoxRow::new();
            card_row.set_widget_name("subscription-card");
            card_row.set_activatable(true);
            card_row.set_selectable(false);
            let selected = item.id == state.settings.active_subscription;
            if selected {
                card_row.add_css_class("subscription-selected");
            }
            card_row.update_property(&[gtk::accessible::Property::Label(&item.name)]);
            card_row.update_state(&[gtk::accessible::State::Selected(Some(selected))]);
            let indicator = gtk::Stack::new();
            indicator.set_size_request(22, 22);
            indicator.set_valign(gtk::Align::Center);
            indicator.add_named(
                &gtk::Image::from_icon_name("object-select-symbolic"),
                Some("chosen"),
            );
            indicator.add_named(
                &gtk::Box::new(gtk::Orientation::Horizontal, 0),
                Some("empty"),
            );
            let spinner = gtk::Spinner::new();
            indicator.add_named(&spinner, Some("busy"));
            indicator.set_visible_child_name(if selected { "chosen" } else { "empty" });
            indicators.borrow_mut().push((indicator.clone(), spinner));
            let count = item
                .nodes
                .iter()
                .filter(|node| model::is_connection_node(node))
                .count();
            let meta = format!("{} 个节点 · {}", count, updated(item.updated));
            let row = resource_row("folder-download-symbolic", &item.name, &meta);
            row.append(&indicator);
            let edit = icon_button("document-edit-symbolic", "订阅设置");
            let weak = Rc::downgrade(self);
            let sub = item.clone();
            edit.connect_clicked(move |_| {
                if let Some(ui) = weak.upgrade() {
                    editors::subscription(&ui.window, ui.service.clone(), sub.clone(), ui.saved());
                }
            });
            row.append(&edit);
            let refresh = icon_button("view-refresh-symbolic", "更新订阅");
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
            row.append(&refresh);
            row.append(&self.delete_button("subscriptions", &item.id, &item.name));
            card.append(&row);
            let footer = gtk::Box::new(gtk::Orientation::Horizontal, 12);
            footer.set_margin_start(20);
            footer.set_margin_end(20);
            footer.set_margin_bottom(16);
            let details = gtk::Box::new(gtk::Orientation::Vertical, 6);
            details.set_hexpand(true);
            if item.total > 0 {
                let used = item.download.saturating_add(item.upload);
                let label = gtk::Label::new(Some(&format!(
                    "已用 {} / {}",
                    bytes(used),
                    bytes(item.total)
                )));
                label.set_xalign(0.0);
                details.append(&label);
                let progress = gtk::ProgressBar::new();
                progress.set_fraction((used as f64 / item.total as f64).min(1.0));
                details.append(&progress);
            }
            let mut status = if item.source.is_empty() {
                "本地导入".into()
            } else if item.auto_update {
                format!("每 {} 小时自动更新", item.update_interval_hours)
            } else {
                "手动更新".into()
            };
            if item.expires > 0 {
                if item.expires <= model::now() {
                    status.push_str(" · 已过期");
                } else {
                    status.push_str(&format!(
                        " · 剩余 {} 天",
                        (item.expires - model::now()).div_ceil(86400)
                    ));
                }
            }
            let label = gtk::Label::new(Some(&status));
            label.set_xalign(0.0);
            label.set_wrap(true);
            label.add_css_class("dim-label");
            details.append(&label);
            footer.append(&details);
            card.append(&footer);
            card_row.set_child(Some(&card));
            list.append(&card_row);
        }
        let weak = Rc::downgrade(self);
        let busy = Rc::new(Cell::new(false));
        list.connect_row_activated(move |list, row| {
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
        .find(|w| w.widget_name() == "subscriptions-list")
        .context("缺少订阅列表")?
        .clone()
        .downcast::<gtk::ListBox>()
        .unwrap();
    let state = ui.service.snapshot();
    ensure!(
        state.settings.active_subscription == state.subscriptions[active].id,
        "点击没有选用订阅"
    );
    for (index, _) in state.subscriptions.iter().enumerate() {
        let row = list.row_at_index(index as i32).unwrap();
        ensure!(
            row.has_css_class("subscription-selected") == (index == active),
            "订阅高亮不准确"
        );
    }
    if let Some(index) = click {
        let row = list.row_at_index(index as i32).unwrap();
        list.emit_by_name::<()>("row-activated", &[&row]);
        ensure!(
            list.row_at_index(active as i32)
                .unwrap()
                .has_css_class("subscription-selected"),
            "选用成功前丢失原高亮"
        );
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
