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
        // Homogeneous keeps cards equal width; without a fixed minimum the
        // FlowBox lets one card fill the row, so the minimum is dropped and the
        // column count alone decides the layout.
        list.set_homogeneous(true);
        list.set_min_children_per_line(2);
        list.set_max_children_per_line(2);
        list.set_column_spacing(16);
        list.set_row_spacing(16);
        list.set_valign(gtk::Align::Start);
        // Subscription cards stay at two columns at most: they carry a name,
        // expiry, progress bar and usage figures that a third column would
        // squeeze below a readable width.
        follow_width(&list, 360, 16, 2, self.typography.preview() >= 16);
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
            // Only cap the natural width; leaving it at one character made the
            // name collapse to an ellipsis as soon as the font grew.
            title.set_width_chars(1);
            title.set_max_width_chars(12);
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
            // Let the expiry text shrink so a large font cannot force the card
            // wider than half the grid.
            expiration.set_ellipsize(gtk::pango::EllipsizeMode::End);
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
            updated.set_ellipsize(gtk::pango::EllipsizeMode::End);
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
            .default_width(560)
            .default_height(470)
            .build();
        if let Some(app) = self.window.application() {
            window.set_application(Some(&app));
        }
        let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
        root.add_css_class("editor-root");
        root.add_css_class("import-dialog");
        let header = adw::HeaderBar::new();
        let import = primary("导入", "document-save-symbolic");
        import.set_widget_name("subscription-import-save");
        header.pack_end(&import);
        root.append(&header);
        let form = gtk::Box::new(gtk::Orientation::Vertical, 12);
        form.set_margin_start(20);
        form.set_margin_end(20);
        form.set_margin_top(12);
        form.set_margin_bottom(20);
        let name = LabeledEntry::new("名称（可选）", "");
        form.append(&name.root);
        let source_title = gtk::Label::new(Some("订阅链接或节点内容"));
        source_title.set_xalign(0.0);
        source_title.add_css_class("labeled-entry-title");
        form.append(&source_title);
        let source = gtk::TextView::builder()
            .wrap_mode(gtk::WrapMode::WordChar)
            .top_margin(9)
            .bottom_margin(9)
            .left_margin(10)
            .right_margin(10)
            .build();
        source.set_widget_name("subscription-import-source");
        let scroll = gtk::ScrolledWindow::builder()
            .child(&source)
            .min_content_height(72)
            .max_content_height(144)
            .propagate_natural_height(true)
            .vexpand(false)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .build();
        scroll.add_css_class("card");
        scroll.add_css_class("import-source");
        form.append(&scroll);
        // Live feedback under the source box: the import button used to be the
        // only place that reported problems, after the user had committed.
        let hint = gtk::Label::builder()
            .xalign(0.0)
            .wrap(true)
            .visible(false)
            .build();
        hint.set_widget_name("subscription-import-hint");
        hint.add_css_class("muted");
        hint.add_css_class("small");
        form.append(&hint);
        let auto_update = switch_row("自动更新", "", true);
        let interval = number_entry(
            "更新间隔（分钟）",
            &model::UPDATE_INTERVAL_DEFAULT_MINUTES.to_string(),
        );
        let interval_toggle = interval.root.clone();
        auto_update
            .connect_active_notify(move |row| interval_toggle.set_sensitive(row.is_active()));
        let updates = adw::PreferencesGroup::new();
        updates.add(&auto_update);
        updates.add(&interval.root);
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
        let busy = Rc::new(Cell::new(false));
        let buffer = source.buffer();
        let validate = {
            // Validate as the text changes so the button state and the hint
            // always agree with what the user typed or pasted.
            let hint = hint.downgrade();
            let error = error.downgrade();
            import.set_sensitive(false);
            let import = import.downgrade();
            let busy = busy.clone();
            let refresh = std::rc::Rc::new(move |buffer: &gtk::TextBuffer| {
                let (Some(import), Some(hint), Some(error)) =
                    (import.upgrade(), hint.upgrade(), error.upgrade())
                else {
                    return;
                };
                if busy.get() {
                    import.set_sensitive(false);
                    return;
                }
                let text = buffer
                    .text(&buffer.start_iter(), &buffer.end_iter(), false)
                    .to_string();
                let trimmed = text.trim();
                if trimmed.is_empty() {
                    hint.set_visible(false);
                    import.set_sensitive(false);
                    return;
                }
                match subscription::import_input(trimmed) {
                    Ok(sub) => {
                        import.set_sensitive(true);
                        error.set_visible(false);
                        hint.set_text(if sub.source.is_empty() {
                            "已识别为节点内容，将保存为本地订阅"
                        } else {
                            "已识别为订阅链接"
                        });
                        hint.set_visible(true);
                    }
                    Err(failure) => {
                        import.set_sensitive(false);
                        error.set_visible(false);
                        hint.set_text(&format!("无法识别：{failure}"));
                        hint.set_visible(true);
                    }
                }
            });
            let changed = refresh.clone();
            buffer.connect_changed(move |buffer| changed(buffer));
            refresh
        };
        let weak = Rc::downgrade(self);
        let weak_window = window.downgrade();
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
            if busy.replace(true) {
                return;
            }
            form.set_sensitive(false);
            let buffer = source.buffer();
            let input = buffer
                .text(&buffer.start_iter(), &buffer.end_iter(), false)
                .to_string();
            let name = name.text().trim().to_owned();
            let auto_update = auto_update.is_active();
            let interval = interval.text().trim().parse().unwrap_or(0);
            let window = weak_window.clone();
            let error = error.clone();
            let busy = busy.clone();
            let form = form.downgrade();
            let validate = validate.clone();
            error.set_visible(false);
            ui.button_task(
                button,
                "导入中…",
                move |s| {
                    let mut sub = subscription::import_input(&input)?;
                    if !name.is_empty() {
                        sub.name = name;
                    }
                    sub.auto_update = auto_update && !sub.source.is_empty();
                    sub.update_interval_minutes = interval;
                    s.import_subscription(sub)
                },
                move |ui, result| {
                    busy.set(false);
                    if let Some(form) = form.upgrade() {
                        form.set_sensitive(true);
                    }
                    validate(&buffer);
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
                let large_text = ui.typography.preview() >= 16;
                if ui.window.width() >= 1100 && !large_text {
                    ensure!(
                        (bounds.y() - first.y()).abs() < 1.0 && bounds.x() > first.x(),
                        "常规窗口没有一行两个订阅: window={} list={} first=({},{} {}x{}) second=({},{} {}x{}) max_cols={}",
                        ui.window.width(),
                        list.width(),
                        first.x(),
                        first.y(),
                        first.width(),
                        first.height(),
                        bounds.x(),
                        bounds.y(),
                        bounds.width(),
                        bounds.height(),
                        list.max_children_per_line()
                    );
                } else if ui.window.width() <= 620 || large_text {
                    ensure!(
                        bounds.y() >= first.y() + first.height(),
                        "空间不足时没有改为单列订阅"
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

pub(super) fn smoke_import_window(ui: &Rc<Ui>) -> Result<adw::Window> {
    let application = ui.window.application().context("缺少应用")?;
    application
        .windows()
        .into_iter()
        .filter_map(|window| window.downcast::<adw::Window>().ok())
        .find(|window| window.title().as_deref() == Some("导入订阅"))
        .context("导入订阅窗口未打开")
}

pub(super) fn smoke_import(ui: &Rc<Ui>, step: u32) -> Result<()> {
    use anyhow::ensure;
    if step == 3 {
        ensure!(ui.jobs.get() == 0, "订阅导入未完成");
        let state = ui.service.snapshot();
        let sub = state
            .subscriptions
            .iter()
            .find(|s| s.name == "导入检查")
            .context("导入订阅没有保存")?;
        ensure!(
            state
                .subscriptions
                .iter()
                .filter(|s| s.name == "导入检查")
                .count()
                == 1,
            "重复点击导入创建了多个订阅"
        );
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
    ensure!(
        widgets
            .iter()
            .filter_map(|w| w.downcast_ref::<gtk::Button>())
            .all(|button| {
                !matches!(
                    button.label().as_deref(),
                    Some("从剪贴板导入" | "从文件导入")
                )
            }),
        "导入窗口仍有已删除的剪贴板或文件入口"
    );
    let interval = widgets
        .iter()
        .filter_map(|w| w.downcast_ref::<gtk::Entry>())
        .find(|entry| entry.placeholder_text().as_deref() == Some("更新间隔（分钟）"))
        .context("缺少分钟更新间隔")?;
    ensure!(
        interval.text() == model::UPDATE_INTERVAL_DEFAULT_MINUTES.to_string(),
        "导入窗口的默认更新间隔无效"
    );
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
            ui.jobs.get() == 0 && source.is_sensitive(),
            "失败后导入表单没有恢复"
        );
        ensure!(!save.is_sensitive(), "无效输入不应重新启用导入按钮");
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
    ensure!(!source.is_sensitive(), "导入期间仍可编辑文本");
    if step == 2 {
        let pending = ui.jobs.get();
        source.buffer().insert_at_cursor(" ");
        ensure!(!save.is_sensitive(), "文本变更重新启用了忙碌的导入按钮");
        // Signal delivery can also come from keyboard/default activation.
        save.emit_clicked();
        ensure!(ui.jobs.get() == pending, "重复点击启动了第二个导入任务");
    }
    Ok(())
}

pub(super) fn smoke_dialog_release(ui: &Rc<Ui>) -> Result<()> {
    let mut retained = Vec::<glib::WeakRef<glib::Object>>::new();
    let app = ui.window.application().context("缺少应用")?;
    for _ in 0..5 {
        ui.import_subscription();
        let window = smoke_import_window(ui)?;
        for widget in descendants(&window) {
            if let Some(source) = widget.downcast_ref::<gtk::TextView>() {
                retained.push(source.buffer().upcast::<glib::Object>().downgrade());
            }
            retained.push(widget.upcast::<glib::Object>().downgrade());
        }
        window.close();
        editors::subscription(
            &ui.window,
            ui.service.clone(),
            Subscription::default(),
            ui.saved(),
        );
        let editor = app
            .windows()
            .into_iter()
            .find(|window| window.title().as_deref() == Some("编辑订阅"))
            .context("缺少订阅编辑弹窗")?;
        for widget in descendants(&editor) {
            retained.push(widget.upcast::<glib::Object>().downgrade());
        }
        editor.close();
    }
    anyhow::ensure!(
        retained.iter().all(|widget| widget.upgrade().is_none()),
        "关闭订阅弹窗后仍有 {} 个控件或缓冲区未释放",
        retained
            .iter()
            .filter(|widget| widget.upgrade().is_some())
            .count()
    );
    Ok(())
}
