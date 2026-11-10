use super::*;
use aerobox_for_linux::engine::SubscriptionNode;

pub(super) struct NodesPanel {
    subscription_id: String,
    picker: gtk::DropDown,
    list: gtk::ListBox,
    empty: gtk::Widget,
    test: gtk::Button,
    data: RefCell<Vec<SubscriptionNode>>,
    rows: RefCell<Vec<NodeRow>>,
    selecting: Cell<bool>,
    testing: Cell<bool>,
    revision: Cell<u64>,
}

struct NodeRow {
    row: gtk::ListBoxRow,
    indicator: gtk::Stack,
    spinner: gtk::Spinner,
    delay: gtk::Label,
}

impl Ui {
    pub(super) fn nodes(self: &Rc<Self>, heading: &gtk::Box) {
        let state = self.service.snapshot();
        if state.subscriptions.is_empty() {
            self.body
                .append(&empty("network-wireless-symbolic", "暂无节点", ""));
            return;
        }
        let active = state
            .profiles
            .iter()
            .find(|p| p.id == state.settings.active_profile);
        let preferred = self.node_subscription.borrow().clone();
        let selected = state
            .subscriptions
            .iter()
            .position(|s| s.id == preferred)
            .or_else(|| {
                active
                    .and_then(|p| p.selected_node.as_ref())
                    .and_then(|node| {
                        state
                            .subscriptions
                            .iter()
                            .position(|s| s.id == node.subscription_id)
                    })
            })
            .or_else(|| {
                active.and_then(|p| {
                    state
                        .subscriptions
                        .iter()
                        .position(|s| p.subscriptions.contains(&s.id))
                })
            })
            .unwrap_or(0);
        let subscription_id = state.subscriptions[selected].id.clone();
        self.node_subscription.replace(subscription_id.clone());
        let names: Vec<_> = state
            .subscriptions
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        let picker = gtk::DropDown::from_strings(&names);
        picker.set_widget_name("node-subscription");
        picker.add_css_class("node-subscription");
        picker.set_selected(selected as u32);
        picker.set_hexpand(true);
        picker.update_property(&[gtk::accessible::Property::Label("选择订阅")]);
        let factory = gtk::SignalListItemFactory::new();
        factory.connect_setup(|_, item| {
            let item = item.downcast_ref::<gtk::ListItem>().unwrap();
            let text = label("", "");
            text.set_ellipsize(gtk::pango::EllipsizeMode::End);
            text.set_width_chars(12);
            text.set_max_width_chars(36);
            item.set_child(Some(&text));
        });
        factory.connect_bind(|_, item| {
            let item = item.downcast_ref::<gtk::ListItem>().unwrap();
            let text = item.child().unwrap().downcast::<gtk::Label>().unwrap();
            let value = item
                .item()
                .unwrap()
                .downcast::<gtk::StringObject>()
                .unwrap();
            text.set_text(&value.string());
        });
        picker.set_factory(Some(&factory));
        self.body.append(&picker);
        let test = gtk::Button::with_label("测速");
        test.add_css_class("compact-action");
        test.set_valign(gtk::Align::Center);
        test.set_widget_name("nodes-test");
        test.set_tooltip_text(Some("测试此订阅的节点延迟"));
        heading.append(&test);
        let list = gtk::ListBox::new();
        list.add_css_class("nodes-list");
        list.set_widget_name("subscription-nodes");
        // Highlight only a successfully applied choice, never the row that was
        // merely clicked or focused while a core operation is still pending.
        list.set_selection_mode(gtk::SelectionMode::None);
        list.set_activate_on_single_click(true);
        list.update_property(&[gtk::accessible::Property::Label("订阅节点")]);
        self.body.append(&list);
        let empty = empty("network-wireless-symbolic", "暂无节点", "");
        self.body.append(&empty);
        let panel = Rc::new(NodesPanel {
            subscription_id,
            picker: picker.clone(),
            list: list.clone(),
            empty: empty.upcast(),
            test: test.clone(),
            data: RefCell::new(vec![]),
            rows: RefCell::new(vec![]),
            selecting: Cell::new(false),
            testing: Cell::new(false),
            revision: Cell::new(0),
        });
        let ids: Vec<_> = state.subscriptions.into_iter().map(|s| s.id).collect();
        let weak = Rc::downgrade(self);
        picker.connect_selected_notify(move |picker| {
            if let (Some(ui), Some(id)) = (weak.upgrade(), ids.get(picker.selected() as usize)) {
                ui.node_subscription.replace(id.clone());
                ui.refresh(Page::Nodes);
            }
        });
        let weak = Rc::downgrade(self);
        let weak_panel = Rc::downgrade(&panel);
        list.connect_row_activated(move |_, row| {
            if let (Some(ui), Some(panel)) = (weak.upgrade(), weak_panel.upgrade()) {
                panel.select(&ui, row.index() as usize);
            }
        });
        let weak = Rc::downgrade(self);
        let weak_panel = Rc::downgrade(&panel);
        test.connect_clicked(move |_| {
            if let (Some(ui), Some(panel)) = (weak.upgrade(), weak_panel.upgrade()) {
                panel.measure(&ui);
            }
        });
        panel.reload_local(self);
        panel.read_runtime(self);
        self.node_panel.replace(Some(panel));
    }
}

impl NodesPanel {
    fn reload_local(&self, ui: &Ui) {
        match ui.service.subscription_nodes(&self.subscription_id) {
            Ok(nodes) => self.display(nodes),
            Err(error) => ui.error("读取节点失败", error),
        }
    }

    fn display(&self, nodes: Vec<SubscriptionNode>) {
        self.list.set_tooltip_text(None);
        let changed = self
            .data
            .borrow()
            .iter()
            .map(|n| &n.node_tag)
            .ne(nodes.iter().map(|n| &n.node_tag));
        if changed {
            self.rows.borrow_mut().clear();
            while let Some(child) = self.list.first_child() {
                self.list.remove(&child);
            }
            for node in &nodes {
                let row = gtk::ListBoxRow::new();
                row.set_selectable(false);
                row.set_activatable(true);
                row.set_widget_name("subscription-node");
                row.update_property(&[gtk::accessible::Property::Label(&node.name)]);
                let line = gtk::Box::new(gtk::Orientation::Horizontal, 12);
                line.add_css_class("node-line");
                let indicator = gtk::Stack::new();
                indicator.set_size_request(20, 20);
                indicator.set_valign(gtk::Align::Center);
                let check = gtk::Image::from_icon_name("object-select-symbolic");
                check.add_css_class("node-check");
                indicator.add_named(&check, Some("chosen"));
                indicator.add_named(
                    &gtk::Box::new(gtk::Orientation::Horizontal, 0),
                    Some("empty"),
                );
                let spinner = gtk::Spinner::new();
                indicator.add_named(&spinner, Some("busy"));
                line.append(&indicator);
                let name = label(&node.name, "node-name");
                name.set_hexpand(true);
                name.set_width_chars(1);
                name.set_ellipsize(gtk::pango::EllipsizeMode::End);
                name.set_tooltip_text(Some(&node.name));
                line.append(&name);
                let delay = label("—", "muted node-delay");
                delay.set_width_chars(8);
                delay.set_xalign(1.0);
                line.append(&delay);
                row.set_child(Some(&line));
                self.list.append(&row);
                self.rows.borrow_mut().push(NodeRow {
                    row,
                    indicator,
                    spinner,
                    delay,
                });
            }
        }
        for (node, row) in nodes.iter().zip(self.rows.borrow().iter()) {
            row.spinner.stop();
            row.indicator
                .set_visible_child_name(if node.selected { "chosen" } else { "empty" });
            if node.selected {
                row.row.add_css_class("node-selected");
            } else {
                row.row.remove_css_class("node-selected");
            }
            row.row
                .update_state(&[gtk::accessible::State::Selected(Some(node.selected))]);
            row.delay.set_text(&delay_text(node.delay_ms));
            row.delay.set_tooltip_text(None);
        }
        self.list.set_visible(!nodes.is_empty());
        self.empty.set_visible(nodes.is_empty());
        self.data.replace(nodes);
        self.controls();
    }

    fn controls(&self) {
        self.list.set_sensitive(!self.selecting.get());
        self.picker.set_sensitive(!self.selecting.get());
        self.test.set_sensitive(
            !self.selecting.get()
                && !self.testing.get()
                && self.data.borrow().iter().any(|n| n.available),
        );
    }

    fn read_runtime(self: &Rc<Self>, ui: &Rc<Ui>) {
        if !ui.service.status().running {
            return;
        }
        let id = self.subscription_id.clone();
        let revision = self.revision.get();
        let pid = ui.service.status().pid;
        let weak = Rc::downgrade(self);
        ui.task_result(
            move |s| s.subscription_nodes_runtime(&id),
            move |ui, result| {
                if let Some(panel) = weak.upgrade()
                    && panel.revision.get() == revision
                    && !panel.selecting.get()
                    && ui.service.status().pid == pid
                {
                    match result {
                        Ok(nodes) => panel.display(nodes),
                        Err(error) => panel.list.set_tooltip_text(Some(&format!("{error:#}"))),
                    }
                }
            },
        );
    }

    fn select(self: &Rc<Self>, ui: &Rc<Ui>, index: usize) {
        if self.selecting.get() {
            return;
        }
        let Some(node) = self.data.borrow().get(index).cloned() else {
            return;
        };
        self.selecting.set(true);
        self.revision.set(self.revision.get() + 1);
        self.controls();
        if let Some(row) = self.rows.borrow().get(index) {
            row.indicator.set_visible_child_name("busy");
            row.spinner.start();
        }
        let weak = Rc::downgrade(self);
        ui.task_result(
            move |s| s.select_subscription_node(&node.subscription_id, &node.node_tag),
            move |ui, result| {
                // Keep focus and scroll position when this selection updates the
                // profile. Subscription refreshes still rebuild the page normally.
                ui.subscription_revision
                    .set(ui.service.subscription_revision());
                if let Some(panel) = weak.upgrade() {
                    panel.selecting.set(false);
                    panel.reload_local(ui);
                    panel.read_runtime(ui);
                }
                if let Err(error) = result {
                    ui.error("选择节点失败", format!("{error:#}"));
                }
            },
        );
    }

    fn measure(self: &Rc<Self>, ui: &Rc<Ui>) {
        if self.testing.get() || self.selecting.get() {
            return;
        }
        let nodes: Vec<_> = self
            .data
            .borrow()
            .iter()
            .filter(|n| n.available)
            .map(|n| (n.subscription_id.clone(), n.node_tag.clone()))
            .collect();
        if nodes.is_empty() {
            return;
        }
        self.testing.set(true);
        let pid = ui.service.status().pid;
        let weak = Rc::downgrade(self);
        ui.button_task(
            &self.test,
            "测速中…",
            move |service| {
                std::thread::scope(|scope| {
                    let tasks: Vec<_> = nodes
                        .chunks(nodes.len().div_ceil(4))
                        .map(|chunk| {
                            scope.spawn(move || {
                                chunk
                                    .iter()
                                    .map(|(id, tag)| {
                                        (tag.clone(), service.test_subscription_node(id, tag))
                                    })
                                    .collect::<Vec<_>>()
                            })
                        })
                        .collect();
                    let mut results = vec![];
                    for task in tasks {
                        results.extend(
                            task.join()
                                .map_err(|_| anyhow::anyhow!("测速任务意外结束"))?,
                        );
                    }
                    Ok(results)
                })
            },
            move |ui, result| {
                let Some(panel) = weak.upgrade() else {
                    return;
                };
                panel.testing.set(false);
                panel.controls();
                if ui.service.status().pid != pid {
                    panel.reload_local(ui);
                    return;
                }
                match result {
                    Ok(results) => {
                        let mut data = panel.data.borrow_mut();
                        let rows = panel.rows.borrow();
                        for (tag, result) in results {
                            if let Some((node, row)) = data
                                .iter_mut()
                                .zip(rows.iter())
                                .find(|(n, _)| n.node_tag == tag)
                            {
                                match result {
                                    Ok(delay) => {
                                        node.delay_ms = Some(delay);
                                        row.delay.set_text(&delay_text(Some(delay)));
                                        row.delay.set_tooltip_text(None);
                                    }
                                    Err(error) => {
                                        node.delay_ms = Some(0);
                                        row.delay.set_text("失败");
                                        row.delay.set_tooltip_text(Some(&format!("{error:#}")));
                                    }
                                }
                            }
                        }
                    }
                    Err(error) => ui.error("测速失败", error),
                }
            },
        );
    }
}

fn delay_text(delay: Option<u64>) -> String {
    match delay {
        Some(0) => "超时".into(),
        Some(ms) => format!("{ms} ms"),
        None => "—".into(),
    }
}

pub(super) fn smoke_nodes(ui: &Rc<Ui>, step: u32) -> Result<()> {
    use anyhow::ensure;
    let panel = ui.node_panel.borrow().clone().context("节点列表未打开")?;
    let state = ui.service.snapshot();
    let active = state
        .profiles
        .iter()
        .find(|p| p.id == state.settings.active_profile)
        .unwrap();
    let chosen_rows = || {
        panel
            .rows
            .borrow()
            .iter()
            .enumerate()
            .filter(|(_, row)| row.row.has_css_class("node-selected"))
            .map(|(i, _)| i)
            .collect::<Vec<_>>()
    };
    let activate = |index: usize| {
        let row = panel.rows.borrow()[index].row.clone();
        panel.list.emit_by_name::<()>("row-activated", &[&row]);
    };
    ensure!(ui.jobs.get() == 0, "节点选择任务没有结束");
    if step > 0 {
        ensure!(
            state.settings.routing_mode == "global",
            "选择节点意外切换了路由模式"
        );
    }
    match step {
        0 => {
            ensure!(
                panel.data.borrow().len() == 6,
                "节点列表混入了分组或其他订阅"
            );
            ensure!(chosen_rows() == vec![1], "已保存节点没有高亮");
            ensure!(!panel.test.is_sensitive(), "未启动时错误启用了测速");
            fn check_controls(widget: &gtk::Widget) -> Result<()> {
                if let Some(label) = widget.downcast_ref::<gtk::Label>() {
                    ensure!(
                        ![
                            "代理组",
                            "路由模式",
                            "规则",
                            "全局",
                            "直连",
                            "自动选择",
                            "默认",
                            "代理"
                        ]
                        .contains(&label.text().as_str()),
                        "节点页混入模式或内部组"
                    );
                }
                ensure!(!widget.is::<gtk::FlowBox>(), "节点页仍在显示卡片分组");
                let mut child = widget.first_child();
                while let Some(widget) = child {
                    child = widget.next_sibling();
                    check_controls(&widget)?;
                }
                Ok(())
            }
            check_controls(ui.body.upcast_ref())?;
            ui.service.set_routing_mode("global")?;
            activate(0);
            ensure!(chosen_rows() == vec![1], "操作成功前提前高亮了节点");
        }
        1 => {
            ensure!(
                chosen_rows() == vec![0]
                    && active
                        .selected_node
                        .as_ref()
                        .is_some_and(|n| n.node_tag == "香港 · 01"),
                "选择后高亮或保存失败"
            );
            ui.navigate(Page::Home);
            ui.navigate(Page::Nodes);
            let reopened = ui.node_panel.borrow().clone().unwrap();
            ensure!(
                reopened.rows.borrow()[0].row.has_css_class("node-selected"),
                "返回节点页丢失了选择"
            );
            reopened.picker.set_selected(1);
        }
        2 => {
            ensure!(panel.data.borrow().len() == 2, "切换订阅没有替换节点列表");
            ensure!(chosen_rows().is_empty(), "跨订阅同名节点被错误高亮");
            ensure!(
                active
                    .selected_node
                    .as_ref()
                    .is_some_and(|n| n.subscription_id == state.subscriptions[0].id),
                "浏览订阅意外切换了出口"
            );
            activate(0);
            ensure!(chosen_rows().is_empty(), "选择完成前出现了错误高亮");
        }
        3 => {
            ensure!(chosen_rows() == vec![0], "新订阅节点没有高亮");
            ensure!(
                active
                    .selected_node
                    .as_ref()
                    .is_some_and(|n| n.subscription_id == state.subscriptions[1].id
                        && n.node_tag == "香港 · 01"),
                "同名节点选错订阅"
            );
            ensure!(
                active.subscriptions.contains(&state.subscriptions[1].id),
                "选择节点没有关联订阅"
            );
            panel.picker.set_selected(0);
        }
        4 => {
            ensure!(chosen_rows().is_empty(), "返回另一订阅时仍高亮同名节点");
            panel.picker.set_selected(1);
            ui.window.set_default_size(700, 600);
        }
        5 => {
            ensure!(chosen_rows() == vec![0], "切换订阅后丢失已选节点");
            for row in panel.rows.borrow().iter() {
                let bounds = row
                    .row
                    .compute_bounds(&ui.scroll)
                    .context("节点行没有分配位置")?;
                ensure!(
                    bounds.x() >= 0.0 && bounds.x() + bounds.width() <= ui.scroll.width() as f32,
                    "窄窗口节点行横向溢出"
                );
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}
