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
        let add = toolbar_action("导入订阅");
        add.set_widget_name("subscription-import");
        heading.append(&add);
        let weak = Rc::downgrade(self);
        add.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.import_subscription();
            }
        });
        let displayed_revision = Rc::new(Cell::new(self.service.subscription_revision()));
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
        // FlClash profile cards: 300px minimum width and at most three columns.
        list.set_homogeneous(true);
        list.set_min_children_per_line(1);
        list.set_max_children_per_line(3);
        list.set_column_spacing(16);
        list.set_row_spacing(12);
        list.set_valign(gtk::Align::Start);
        follow_width(&list, 300, 16, 3, true);
        let ids: Vec<_> = state
            .subscriptions
            .iter()
            .map(|sub| sub.id.clone())
            .collect();
        let indicators = Rc::new(RefCell::new(Vec::<(gtk::Stack, gtk::Spinner)>::new()));
        for item in state.subscriptions {
            let content = gtk::Box::new(gtk::Orientation::Vertical, 8);
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
            let header = gtk::Box::new(gtk::Orientation::Horizontal, 5);
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
            indicator.set_size_request(16, 16);
            indicator.set_valign(gtk::Align::Center);
            indicator.add_named(
                &gtk::Box::new(gtk::Orientation::Horizontal, 0),
                Some("empty"),
            );
            let spinner = gtk::Spinner::new();
            spinner.add_css_class("compact-spinner");
            indicator.add_named(&spinner, Some("busy"));
            indicator.set_visible_child_name("empty");
            indicators.borrow_mut().push((indicator.clone(), spinner));
            header.append(&indicator);
            if item.expires > 0 {
                let expiry = format!("{} 到期", format_timestamp(item.expires, "%Y-%m-%d"));
                let expiration = label(&expiry, "subscription-expiry muted small");
                expiration.set_widget_name("subscription-expiry");
                expiration.set_ellipsize(gtk::pango::EllipsizeMode::End);
                if item.expires <= model::now() {
                    expiration.add_css_class("error");
                }
                title.set_tooltip_text(Some(&format!("{} · {}", item.name, expiry)));
                header.append(&expiration);
            }
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
                        move |s| {
                            s.update_subscription(&id)?;
                            Ok(id)
                        },
                        |ui, result| match result {
                            Ok(id) => {
                                ui.refresh(Page::Subscriptions);
                                if let Some(sub) = ui
                                    .service
                                    .snapshot()
                                    .subscriptions
                                    .into_iter()
                                    .find(|s| s.id == id)
                                {
                                    ui.notify(&format!("订阅已更新 · {} 个节点", sub.nodes.len()));
                                }
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
            if item.total > 0 {
                progress.set_fraction((used as f64 / item.total as f64).min(1.0));
            }
            content.append(&progress);
            let footer = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            let info = label(
                &if item.total > 0 {
                    format!("已用 {} / {}", bytes(used), bytes(item.total))
                } else if item.source.is_empty() {
                    "本地订阅".into()
                } else {
                    "在线订阅".into()
                },
                "subscription-usage muted",
            );
            info.set_widget_name("subscription-usage");
            info.set_hexpand(true);
            info.set_width_chars(1);
            info.set_ellipsize(gtk::pango::EllipsizeMode::End);
            info.set_tooltip_text(Some(&if item.total > 0 {
                format!("已用 {}，总量 {}", bytes(used), bytes(item.total))
            } else {
                "订阅未提供流量信息".into()
            }));
            footer.append(&info);
            let updated = label(
                &if item.updated == 0 {
                    "尚未更新".into()
                } else {
                    format_timestamp(item.updated, "%m-%d %H:%M")
                },
                "subscription-updated muted small",
            );
            updated.set_widget_name("subscription-updated");
            updated.set_xalign(1.0);
            updated.set_tooltip_text(Some(&if item.updated == 0 {
                "尚未更新".into()
            } else {
                format!(
                    "更新于 {}",
                    format_timestamp(item.updated, "%Y-%m-%d %H:%M")
                )
            }));
            footer.append(&updated);
            content.append(&footer);
            card.set_child(Some(&content));
            list.insert(&card, -1);
        }

        let weak = Rc::downgrade(self);
        let busy = Rc::new(Cell::new(false));
        list.connect_child_activated(move |list, row| {
            if busy.get() {
                return;
            }
            let (Some(ui), Some(id)) = (weak.upgrade(), ids.get(row.index() as usize)) else {
                return;
            };
            if ui.service.snapshot().settings.active_subscription == *id {
                return;
            }
            busy.set(true);
            let id = id.clone();
            let (indicator, spinner) = indicators.borrow()[row.index() as usize].clone();
            indicator.set_visible_child_name("busy");
            spinner.start();
            let list = list.downgrade();
            let busy = busy.clone();
            let ids = ids.clone();
            let indicators = indicators.clone();
            let displayed_revision = displayed_revision.clone();
            ui.task_result(
                move |s| s.select_subscription(&id),
                move |ui, result| {
                    busy.set(false);
                    spinner.stop();
                    if let Some(list) = list.upgrade()
                        && list.is_ancestor(&ui.body)
                    {
                        let revision = ui.service.subscription_revision();
                        ui.subscription_revision.set(revision);
                        // A concurrent subscription update still needs to render
                        // its changed name, usage or card list.
                        if revision != displayed_revision.get() + u64::from(result.is_ok()) {
                            ui.refresh(Page::Subscriptions);
                        } else {
                            let state = ui.service.snapshot();
                            for (index, (id, (indicator, spinner))) in
                                ids.iter().zip(indicators.borrow().iter()).enumerate()
                            {
                                let selected = state.settings.active_subscription == *id;
                                if let Some(card) = list.child_at_index(index as i32) {
                                    if selected {
                                        card.add_css_class("subscription-selected");
                                    } else {
                                        card.remove_css_class("subscription-selected");
                                    }
                                    card.update_state(&[gtk::accessible::State::Selected(Some(
                                        selected,
                                    ))]);
                                }
                                spinner.stop();
                                indicator.set_visible_child_name("empty");
                            }
                            displayed_revision.set(revision);
                        }
                    }
                    if let Err(error) = result {
                        ui.error("切换订阅失败", format!("{error:#}"));
                    }
                },
            );
        });
        self.body.append(&list);
    }

    pub(super) fn import_subscription(self: &Rc<Self>) {
        let dialog = dialog_header(
            &self.window,
            "导入订阅",
            "导入",
            "document-save-symbolic",
            DialogLayout::Form,
        );
        let window = dialog.window;
        let root = dialog.root;
        root.add_css_class("import-dialog");
        let import = dialog.action;
        import.set_widget_name("subscription-import-save");
        let (form_scroll, form) = dialog_form();
        let basic = gtk::Box::new(gtk::Orientation::Vertical, 0);
        basic.add_css_class("dialog-fields");
        form.append(&basic);
        let name = LabeledEntry::new("名称（可选）", "");
        name.entry.set_placeholder_text(Some("留空时自动识别"));
        basic.append(&name.root);
        let source_title = gtk::Label::new(Some("订阅链接或节点内容"));
        source_title.set_xalign(0.0);
        source_title.add_css_class("labeled-entry-title");
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
        scroll.add_css_class("import-source");
        let source_field = gtk::Box::new(gtk::Orientation::Vertical, 6);
        source_field.add_css_class("source-field");
        source_field.append(&source_title);
        source_field.append(&scroll);
        basic.append(&source_field);
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
        let (updates, auto_update, interval) =
            update_controls(true, model::UPDATE_INTERVAL_DEFAULT_MINUTES);
        form.append(&updates);
        let error = gtk::Label::builder()
            .wrap(true)
            .xalign(0.0)
            .visible(false)
            .selectable(true)
            .build();
        error.set_widget_name("subscription-import-error");
        error.add_css_class("error");
        error.add_css_class("dialog-error");
        form.append(&error);
        root.append(&form_scroll);
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
            let auto_update = auto_update.downgrade();
            let refresh = std::rc::Rc::new(move |buffer: &gtk::TextBuffer| {
                let (Some(import), Some(hint), Some(error), Some(auto_update)) = (
                    import.upgrade(),
                    hint.upgrade(),
                    error.upgrade(),
                    auto_update.upgrade(),
                ) else {
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
                    auto_update.set_sensitive(true);
                    import.set_sensitive(false);
                    return;
                }
                match subscription::import_input(trimmed) {
                    Ok(sub) => {
                        auto_update.set_sensitive(!sub.source.is_empty());
                        import.set_sensitive(true);
                        error.set_visible(false);
                        hint.set_text(&if sub.source.is_empty() {
                            format!(
                                "识别到 {} 个节点{}",
                                sub.nodes.len(),
                                if sub.import_issues.is_empty() {
                                    String::new()
                                } else {
                                    format!("，{} 个节点无法导入", sub.import_issues.len())
                                }
                            )
                        } else {
                            "已识别为订阅链接".into()
                        });
                        hint.set_visible(true);
                    }
                    Err(failure) => {
                        auto_update.set_sensitive(false);
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
        let cancel = dialog.cancel;
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
            let buffer = source.buffer();
            let input = buffer
                .text(&buffer.start_iter(), &buffer.end_iter(), false)
                .to_string();
            let name = name.text().trim().to_owned();
            let auto_update = auto_update.is_active() && auto_update.is_sensitive();
            let interval = if auto_update {
                interval.text().trim().parse().unwrap_or(0)
            } else {
                model::UPDATE_INTERVAL_DEFAULT_MINUTES
            };
            form.set_sensitive(false);
            cancel.set_sensitive(false);
            let window = weak_window.clone();
            let error = error.clone();
            let cancel = cancel.downgrade();
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
                    let id = sub.id.clone();
                    s.import_subscription(sub)?;
                    Ok(id)
                },
                move |ui, result| {
                    busy.set(false);
                    if let Some(form) = form.upgrade() {
                        form.set_sensitive(true);
                    }
                    if let Some(cancel) = cancel.upgrade() {
                        cancel.set_sensitive(true);
                    }
                    validate(&buffer);
                    match result {
                        Ok(id) => {
                            if let Some(window) = window.upgrade() {
                                window.close();
                            }
                            ui.refresh(Page::Subscriptions);
                            if let Some(sub) = ui
                                .service
                                .snapshot()
                                .subscriptions
                                .into_iter()
                                .find(|s| s.id == id)
                            {
                                ui.notify(&format!("已导入 {} 个节点", sub.nodes.len()));
                            }
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

pub(super) fn update_controls(
    active: bool,
    minutes: u32,
) -> (gtk::Box, adw::SwitchRow, LabeledEntry) {
    let toggle = switch_row("自动更新", "", active);
    let interval = number_entry("更新间隔（分钟）", &minutes.to_string());
    interval.root.set_visible(active);
    let weak_interval = interval.root.downgrade();
    toggle.connect_active_notify(move |row| {
        if let Some(interval) = weak_interval.upgrade() {
            interval.set_visible(row.is_active() && row.is_sensitive());
        }
    });
    let weak_interval = interval.root.downgrade();
    toggle.connect_sensitive_notify(move |row| {
        if let Some(interval) = weak_interval.upgrade() {
            interval.set_visible(row.is_active() && row.is_sensitive());
        }
    });
    let group = adw::PreferencesGroup::new();
    group.add(&toggle);
    let root = gtk::Box::new(gtk::Orientation::Vertical, 12);
    root.append(&group);
    root.append(&interval.root);
    (root, toggle, interval)
}

fn format_timestamp(timestamp: u64, pattern: &str) -> String {
    i64::try_from(timestamp)
        .ok()
        .and_then(|value| glib::DateTime::from_unix_local(value).ok())
        .and_then(|date| date.format(pattern).ok())
        .map(|date| date.to_string())
        .unwrap_or_else(|| "—".into())
}

#[cfg(feature = "ui-smoke")]
pub(super) async fn smoke_selection(
    ui: &Rc<Ui>,
    active: usize,
    click: Option<usize>,
) -> Result<()> {
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
    for (index, subscription) in state.subscriptions.iter().enumerate() {
        let row = list.child_at_index(index as i32).unwrap();
        ensure!(
            row.has_css_class("subscription-selected") == (index == active),
            "订阅高亮不准确"
        );
        let parts = descendants(&row);
        ensure!(
            !parts
                .iter()
                .filter_map(|widget| widget.downcast_ref::<gtk::Image>())
                .any(|image| image.icon_name().as_deref() == Some("object-select-symbolic")),
            "订阅卡片仍显示选中角标"
        );
        ensure!(
            parts
                .iter()
                .any(|widget| widget.widget_name() == "subscription-expiry")
                == (subscription.expires > 0),
            "订阅日期显示与到期信息不一致"
        );
        if row.width() > 0 && list.width() > 0 {
            let bounds = row.compute_bounds(&list).context("订阅卡片没有位置")?;
            ensure!(
                bounds.x() >= 0.0 && bounds.x() + bounds.width() <= list.width() as f32 + 1.0,
                "订阅卡片超出页面"
            );
            let get = |name: &str| -> Result<gtk::graphene::Rect> {
                parts
                    .iter()
                    .find(|w| w.widget_name() == name)
                    .context("订阅卡片缺少信息")?
                    .compute_bounds(&row)
                    .context("订阅卡片信息没有位置")
            };
            let name = get("subscription-name")?;
            let progress = get("subscription-progress")?;
            let usage = get("subscription-usage")?;
            let updated = get("subscription-updated")?;
            ensure!(
                name.y() + name.height() <= progress.y()
                    && progress.y() + progress.height() <= usage.y()
                    && (usage.y() - updated.y()).abs() <= 2.0,
                "订阅进度条与流量、更新时间布局不正确"
            );
            if subscription.expires > 0 {
                let expiry = get("subscription-expiry")?;
                ensure!(
                    (name.y() - expiry.y()).abs() < 2.0
                        && expiry.y() + expiry.height() <= progress.y(),
                    "名称和有效期不在同一行"
                );
            }
            ensure!(usage.width() > 0.0, "订阅缺少流量信息");
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
        let scroll = ui.scroll.vadjustment().value();
        let row = list.child_at_index(index as i32).unwrap();
        list.emit_by_name::<()>("child-activated", &[&row]);
        ensure!(
            list.child_at_index(active as i32)
                .unwrap()
                .has_css_class("subscription-selected"),
            "选用成功前丢失原高亮"
        );
        let start = std::time::Instant::now();
        while ui.jobs.get() != 0 {
            ensure!(start.elapsed() < Duration::from_secs(5), "切换订阅未完成");
            glib::timeout_future(Duration::from_millis(20)).await;
        }
        ensure!(
            list.is_ancestor(&ui.body)
                && list.child_at_index(index as i32).as_ref() == Some(&row)
                && (ui.scroll.vadjustment().value() - scroll).abs() < 1.0,
            "切换订阅重建了卡片或重置了滚动位置"
        );
        ensure!(
            row.has_css_class("subscription-selected")
                && ui.service.snapshot().settings.active_subscription
                    == state.subscriptions[index].id,
            "切换订阅后没有就地更新选中项"
        );
    }
    let selected = list.child_at_index(click.unwrap_or(active) as i32).unwrap();
    let revision = ui.service.subscription_revision();
    list.emit_by_name::<()>("child-activated", &[&selected]);
    ensure!(
        ui.jobs.get() == 0 && ui.service.subscription_revision() == revision,
        "点击已选订阅仍然发起后台操作"
    );
    Ok(())
}

#[cfg(feature = "ui-smoke")]
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

#[cfg(feature = "ui-smoke")]
pub(super) fn smoke_import_window(ui: &Rc<Ui>) -> Result<adw::Window> {
    let application = ui.window.application().context("缺少应用")?;
    application
        .windows()
        .into_iter()
        .filter_map(|window| window.downcast::<adw::Window>().ok())
        .find(|window| window.title().as_deref() == Some("导入订阅"))
        .context("导入订阅窗口未打开")
}

#[cfg(feature = "ui-smoke")]
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
            state.settings.active_subscription == state.subscriptions[0].id
                && state.subscriptions[0].selected_node.as_deref() == Some("日本 · 01"),
            "导入订阅改变了原有订阅或节点选择"
        );
        ensure!(
            state.subscriptions.iter().position(|s| s.id == sub.id) == Some(2)
                && !sub.id.is_empty(),
            "导入的订阅没有按新卡片保存"
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
    let auto_update = widgets
        .iter()
        .filter_map(|widget| widget.downcast_ref::<adw::SwitchRow>())
        .find(|row| row.title() == "自动更新")
        .context("缺少自动更新开关")?;
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
    let before = ui.service.snapshot();
    ensure!(
        before.settings.active_subscription == before.subscriptions[0].id
            && before.subscriptions[0].selected_node.as_deref() == Some("日本 · 01"),
        "打开导入窗口改变了原有订阅或节点选择"
    );
    if step == 1 {
        source.buffer().set_text("");
        ensure!(
            auto_update.is_visible() && auto_update.is_sensitive(),
            "空白导入窗口隐藏或禁用了自动更新"
        );
        auto_update.set_active(false);
        ensure!(
            !interval.parent().unwrap().is_visible(),
            "关闭自动更新仍显示间隔"
        );
        source
            .buffer()
            .set_text("https://subscription.example.test/link");
        ensure!(
            auto_update.is_sensitive() && !auto_update.is_active(),
            "输入链接重置了更新选择"
        );
        auto_update.set_active(true);
        ensure!(
            interval.parent().unwrap().is_visible(),
            "开启自动更新未显示间隔"
        );
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
        ensure!(
            auto_update.is_visible()
                && !auto_update.is_sensitive()
                && !interval.parent().unwrap().is_visible(),
            "粘贴节点时自动更新没有保持可见且禁用"
        );
    }
    save.emit_clicked();
    ensure!(
        ui.service.snapshot().settings.active_subscription == before.settings.active_subscription,
        "点击导入后立即改变了当前订阅"
    );
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

#[cfg(feature = "ui-smoke")]
pub(super) fn smoke_dialog_release(ui: &Rc<Ui>) -> Result<()> {
    let mut retained = Vec::<glib::WeakRef<glib::Object>>::new();
    let app = ui.window.application().context("缺少应用")?;
    ui.navigate(Page::Subscriptions);
    anyhow::ensure!(
        !descendants(&ui.body)
            .iter()
            .any(|widget| widget.widget_name() == "subscription-edit-nodes"),
        "订阅卡片仍显示节点编辑铅笔"
    );
    // The card no longer exposes a pencil. Reach the node data the way a user
    // does: the card's subscription settings action, then its explicit button.
    let active = ui.service.snapshot().settings.active_subscription;
    let open_settings = descendants(&ui.body)
        .into_iter()
        .filter_map(|widget| widget.downcast::<gtk::Button>().ok())
        .find(|button| button.label().as_deref() == Some("订阅设置"))
        .context("订阅卡片缺少订阅设置入口")?;
    open_settings.emit_clicked();
    let settings = app
        .windows()
        .into_iter()
        .find(|window| window.title().as_deref() == Some("编辑订阅"))
        .context("订阅设置未打开")?;
    let edit_nodes = descendants(&settings)
        .into_iter()
        .filter_map(|widget| widget.downcast::<gtk::Button>().ok())
        .find(|button| button.label().as_deref() == Some("编辑节点数据"))
        .context("订阅设置缺少编辑节点数据入口")?;
    edit_nodes.emit_clicked();
    let editor = app
        .windows()
        .into_iter()
        .find(|window| {
            window
                .title()
                .is_some_and(|title| title.ends_with(" · 节点"))
        })
        .context("订阅设置没有打开节点编辑")?;
    anyhow::ensure!(
        descendants(&editor).iter().any(|widget| widget
            .downcast_ref::<sourceview::View>()
            .is_some_and(|view| view.is_editable())),
        "节点配置不可编辑"
    );
    anyhow::ensure!(
        !descendants(&editor).iter().any(|widget| widget
            .downcast_ref::<gtk::Button>()
            .and_then(gtk::Button::label)
            .is_some_and(|label| matches!(
                label.as_str(),
                "复制" | "导出文件" | "打开文件" | "格式化"
            ))),
        "节点编辑仍显示快捷工具栏"
    );
    anyhow::ensure!(
        ui.service.snapshot().settings.active_subscription == active,
        "编辑节点改变了订阅选择"
    );
    editor.close();
    settings.close();
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
