use super::*;
use aerobox_for_linux::engine::SubscriptionNode;
use std::collections::HashSet;

pub(super) struct NodesPanel {
    subscription_id: String,
    grid: gtk::FlowBox,
    empty: gtk::Widget,
    test: gtk::Button,
    data: RefCell<Vec<SubscriptionNode>>,
    cards: RefCell<Vec<NodeCard>>,
    selecting: Cell<bool>,
    testing: Cell<bool>,
    pending: RefCell<HashSet<String>>,
    revision: Cell<u64>,
}

struct NodeCard {
    child: gtk::FlowBoxChild,
    indicator: gtk::Stack,
    spinner: gtk::Spinner,
    delay: gtk::Label,
    test: gtk::Button,
    test_indicator: gtk::Stack,
    test_spinner: gtk::Spinner,
}

impl Ui {
    pub(super) fn nodes(self: &Rc<Self>, heading: &gtk::Box) {
        let state = self.service.snapshot();
        let Some(subscription) = state
            .subscriptions
            .iter()
            .find(|s| s.id == state.settings.active_subscription)
        else {
            self.body
                .append(&empty("network-wireless-symbolic", "暂无节点", ""));
            let choose = gtk::Button::with_label("选择订阅");
            choose.set_halign(gtk::Align::Center);
            let weak = Rc::downgrade(self);
            choose.connect_clicked(move |_| {
                if let Some(ui) = weak.upgrade() {
                    ui.navigate(Page::Subscriptions);
                }
            });
            self.body.append(&choose);
            return;
        };
        let subscription_id = subscription.id.clone();
        let name = label(&subscription.name, "muted");
        name.set_ellipsize(gtk::pango::EllipsizeMode::End);
        self.body.append(&name);
        let test = gtk::Button::with_label("测速");
        test.add_css_class("compact-action");
        test.set_valign(gtk::Align::Center);
        test.set_widget_name("nodes-test");
        test.set_tooltip_text(Some("测试此订阅的节点延迟"));
        heading.append(&test);
        let grid = gtk::FlowBox::new();
        grid.add_css_class("nodes-grid");
        grid.set_hexpand(true);
        grid.set_widget_name("subscription-nodes");
        grid.set_selection_mode(gtk::SelectionMode::None);
        grid.set_activate_on_single_click(true);
        grid.set_homogeneous(true);
        grid.set_min_children_per_line(1);
        grid.set_max_children_per_line(4);
        grid.set_column_spacing(12);
        grid.set_row_spacing(12);
        grid.set_valign(gtk::Align::Start);
        follow_width(&grid, 232, 12, 4);
        grid.update_property(&[gtk::accessible::Property::Label("订阅节点")]);
        self.body.append(&grid);
        let empty = empty("network-wireless-symbolic", "暂无节点", "");
        self.body.append(&empty);
        let panel = Rc::new(NodesPanel {
            subscription_id,
            grid: grid.clone(),
            empty: empty.upcast(),
            test: test.clone(),
            data: RefCell::new(vec![]),
            cards: RefCell::new(vec![]),
            selecting: Cell::new(false),
            testing: Cell::new(false),
            pending: RefCell::new(HashSet::new()),
            revision: Cell::new(0),
        });
        let weak = Rc::downgrade(self);
        let weak_panel = Rc::downgrade(&panel);
        // FlowBoxChild supplies native pointer and keyboard activation. Its
        // descendant test button consumes its own activation independently.
        grid.connect_child_activated(move |_, child| {
            if let (Some(ui), Some(panel)) = (weak.upgrade(), weak_panel.upgrade()) {
                panel.select(&ui, child.index() as usize);
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
    fn reload_local(self: &Rc<Self>, ui: &Rc<Ui>) {
        match ui.service.subscription_nodes(&self.subscription_id) {
            Ok(nodes) => self.display(ui, nodes),
            Err(error) => ui.error("读取节点失败", error),
        }
    }

    fn display(self: &Rc<Self>, ui: &Rc<Ui>, mut nodes: Vec<SubscriptionNode>) {
        self.grid.set_tooltip_text(None);
        let changed = self
            .data
            .borrow()
            .iter()
            .map(|n| (&n.node_tag, &n.protocol))
            .ne(nodes.iter().map(|n| (&n.node_tag, &n.protocol)));
        if changed {
            self.cards.borrow_mut().clear();
            while let Some(child) = self.grid.first_child() {
                self.grid.remove(&child);
            }
            for node in &nodes {
                let child = gtk::FlowBoxChild::new();
                child.add_css_class("node-card");
                child.set_widget_name("subscription-node");
                child.set_focusable(true);
                // Cards share the row width instead of a fixed 220px, so the
                // grid fills wide windows and reflows evenly in narrow ones.
                child.set_hexpand(true);
                child.update_property(&[gtk::accessible::Property::Label(&node.name)]);
                let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
                content.add_css_class("node-card-content");
                let title = gtk::Box::new(gtk::Orientation::Horizontal, 8);
                title.set_vexpand(true);
                let name = label(&node.name, "node-name");
                name.set_hexpand(true);
                name.set_valign(gtk::Align::Start);
                name.set_wrap(true);
                name.set_wrap_mode(gtk::pango::WrapMode::WordChar);
                name.set_lines(2);
                name.set_width_chars(1);
                name.set_max_width_chars(22);
                name.set_ellipsize(gtk::pango::EllipsizeMode::End);
                name.set_tooltip_text(Some(&node.name));
                title.append(&name);
                let indicator = gtk::Stack::new();
                indicator.set_size_request(20, 20);
                indicator.set_valign(gtk::Align::Start);
                let check = gtk::Image::from_icon_name("object-select-symbolic");
                check.add_css_class("node-check");
                indicator.add_named(&check, Some("chosen"));
                indicator.add_named(
                    &gtk::Box::new(gtk::Orientation::Horizontal, 0),
                    Some("empty"),
                );
                let spinner = gtk::Spinner::new();
                indicator.add_named(&spinner, Some("busy"));
                title.append(&indicator);
                content.append(&title);
                let footer = gtk::Box::new(gtk::Orientation::Horizontal, 8);
                footer.add_css_class("node-card-footer");
                let protocol = label(&node.protocol, "muted node-protocol");
                protocol.set_hexpand(true);
                protocol.set_width_chars(1);
                protocol.set_ellipsize(gtk::pango::EllipsizeMode::End);
                footer.append(&protocol);
                let delay = label("—", "muted node-delay");
                delay.set_xalign(1.0);
                footer.append(&delay);
                let test = gtk::Button::new();
                test.add_css_class("flat");
                test.add_css_class("node-test-button");
                test.set_widget_name("node-test");
                test.set_valign(gtk::Align::Center);
                test.set_tooltip_text(Some("测试此节点延迟"));
                test.update_property(&[gtk::accessible::Property::Label(&format!(
                    "测试 {} 延迟",
                    node.name
                ))]);
                let test_indicator = gtk::Stack::new();
                test_indicator.set_size_request(18, 18);
                test_indicator.add_named(
                    &gtk::Image::from_icon_name("network-transmit-receive-symbolic"),
                    Some("icon"),
                );
                let test_spinner = gtk::Spinner::new();
                test_indicator.add_named(&test_spinner, Some("busy"));
                test.set_child(Some(&test_indicator));
                let weak = Rc::downgrade(ui);
                let weak_panel = Rc::downgrade(self);
                let tag = node.node_tag.clone();
                test.connect_clicked(move |_| {
                    if let (Some(ui), Some(panel)) = (weak.upgrade(), weak_panel.upgrade()) {
                        panel.measure_one(&ui, &tag);
                    }
                });
                // GTK skips insensitive widgets during pointer picking. Keep
                // their hit area from falling through to card activation.
                let test_slot = gtk::Box::new(gtk::Orientation::Horizontal, 0);
                test_slot.append(&test);
                let guard = gtk::GestureClick::new();
                guard.set_propagation_phase(gtk::PropagationPhase::Capture);
                let weak_button = test.downgrade();
                guard.connect_pressed(move |gesture, _, _, _| {
                    if weak_button
                        .upgrade()
                        .is_some_and(|button| !button.is_sensitive())
                    {
                        gesture.set_state(gtk::EventSequenceState::Claimed);
                    }
                });
                test_slot.add_controller(guard);
                footer.append(&test_slot);
                content.append(&footer);
                child.set_child(Some(&content));
                self.grid.insert(&child, -1);
                self.cards.borrow_mut().push(NodeCard {
                    child,
                    indicator,
                    spinner,
                    delay,
                    test,
                    test_indicator,
                    test_spinner,
                });
            }
        }
        let previous = self.data.borrow();
        for (node, card) in nodes.iter_mut().zip(self.cards.borrow().iter()) {
            card.spinner.stop();
            card.indicator
                .set_visible_child_name(if node.selected { "chosen" } else { "empty" });
            if node.selected {
                card.child.add_css_class("node-selected");
            } else {
                card.child.remove_css_class("node-selected");
            }
            card.child
                .update_state(&[gtk::accessible::State::Selected(Some(node.selected))]);
            if node.delay_ms.is_none() {
                node.delay_ms = previous
                    .iter()
                    .find(|old| old.node_tag == node.node_tag)
                    .and_then(|old| old.delay_ms);
            }
            card.delay.set_text(&delay_text(node.delay_ms));
        }
        drop(previous);
        self.grid.set_visible(!nodes.is_empty());
        self.empty.set_visible(nodes.is_empty());
        self.data.replace(nodes);
        self.controls();
    }

    fn controls(&self) {
        self.grid.set_sensitive(!self.selecting.get());
        let pending = self.pending.borrow();
        self.test.set_sensitive(
            !self.selecting.get()
                && !self.testing.get()
                && pending.is_empty()
                && self.data.borrow().iter().any(|n| n.available),
        );
        for (node, card) in self.data.borrow().iter().zip(self.cards.borrow().iter()) {
            let busy = pending.contains(&node.node_tag);
            card.test.set_sensitive(
                node.available && !self.selecting.get() && !self.testing.get() && !busy,
            );
            card.test.set_tooltip_text(Some(if node.available {
                "测试此节点延迟"
            } else {
                "启动内核后测速"
            }));
            card.test_spinner.set_spinning(busy);
            card.test_indicator
                .set_visible_child_name(if busy { "busy" } else { "icon" });
        }
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
                    && panel.pending.borrow().is_empty()
                    && ui.service.status().pid == pid
                {
                    match result {
                        Ok(nodes) => panel.display(ui, nodes),
                        Err(error) => panel.grid.set_tooltip_text(Some(&format!("{error:#}"))),
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
        if let Some(card) = self.cards.borrow().get(index) {
            card.indicator.set_visible_child_name("busy");
            card.spinner.start();
        }
        let weak = Rc::downgrade(self);
        ui.task_result(
            move |s| s.select_subscription_node(&node.subscription_id, &node.node_tag),
            move |ui, result| {
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

    fn measure_one(self: &Rc<Self>, ui: &Rc<Ui>, tag: &str) {
        if self.selecting.get() || self.testing.get() || self.pending.borrow().contains(tag) {
            return;
        }
        let Some(node) = self
            .data
            .borrow()
            .iter()
            .find(|n| n.node_tag == tag)
            .cloned()
        else {
            return;
        };
        if !node.available {
            return;
        }
        self.pending.borrow_mut().insert(tag.into());
        self.revision.set(self.revision.get() + 1);
        self.controls();
        let pid = ui.service.status().pid;
        let tag = tag.to_owned();
        let weak = Rc::downgrade(self);
        ui.task_result(
            move |service| service.test_subscription_node(&node.subscription_id, &node.node_tag),
            move |ui, result| {
                let Some(panel) = weak.upgrade() else {
                    return;
                };
                panel.pending.borrow_mut().remove(&tag);
                panel.controls();
                if ui.service.status().pid != pid {
                    panel.reload_local(ui);
                    return;
                }
                panel.show_delay(&tag, result, pid.is_none());
            },
        );
    }

    fn show_delay(&self, tag: &str, result: Result<u64>, stopped: bool) {
        let mut data = self.data.borrow_mut();
        let cards = self.cards.borrow();
        if let Some((node, card)) = data
            .iter_mut()
            .zip(cards.iter())
            .find(|(n, _)| n.node_tag == tag)
        {
            match result {
                Ok(delay) => {
                    node.delay_ms = Some(delay);
                    card.delay.set_text(&delay_text(Some(delay)));
                    card.delay.set_tooltip_text(None);
                }
                Err(error) => {
                    node.delay_ms = None;
                    card.delay.set_text(if stopped { "未启动" } else { "失败" });
                    card.delay.set_tooltip_text(Some(&format!("{error:#}")));
                }
            }
        }
    }

    fn measure(self: &Rc<Self>, ui: &Rc<Ui>) {
        if self.testing.get() || self.selecting.get() || !self.pending.borrow().is_empty() {
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
        self.revision.set(self.revision.get() + 1);
        self.pending
            .borrow_mut()
            .extend(nodes.iter().map(|(_, tag)| tag.clone()));
        self.controls();
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
                panel.pending.borrow_mut().clear();
                panel.controls();
                if ui.service.status().pid != pid {
                    panel.reload_local(ui);
                    return;
                }
                match result {
                    Ok(results) => {
                        for (tag, result) in results {
                            panel.show_delay(&tag, result, false);
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

pub(super) fn smoke_nodes(
    ui: &Rc<Ui>,
    subscription: &str,
    count: usize,
    selected: Option<&str>,
    click: Option<usize>,
) -> Result<()> {
    use anyhow::ensure;
    ensure!(ui.jobs.get() == 0, "节点任务未完成");
    let panel = ui.node_panel.borrow().clone().context("节点页未打开")?;
    let state = ui.service.snapshot();
    let active = state
        .subscriptions
        .iter()
        .find(|s| s.id == state.settings.active_subscription)
        .context("缺少所选订阅")?;
    ensure!(
        active.name == subscription && panel.subscription_id == active.id,
        "节点页未跟随所选订阅"
    );
    ensure!(
        panel.data.borrow().len() == count,
        "卡片混入其他订阅或代理组"
    );
    let highlighted: Vec<_> = panel
        .data
        .borrow()
        .iter()
        .zip(panel.cards.borrow().iter())
        .filter(|(_, card)| card.child.has_css_class("node-selected"))
        .map(|(n, _)| n.node_tag.clone())
        .collect();
    if let Some(selected) = selected {
        ensure!(highlighted == vec![selected], "所选节点没有高亮");
    }
    for card in panel.cards.borrow().iter() {
        let bounds = card
            .child
            .compute_bounds(&panel.grid)
            .context("节点卡片没有位置")?;
        ensure!(
            bounds.width() > 0.0
                && bounds.x() >= -1.0
                && bounds.x() + bounds.width() <= panel.grid.width() as f32 + 1.0,
            "节点卡片超出网格边界"
        );
        let test = card
            .test
            .compute_bounds(&card.child)
            .context("测速按钮没有位置")?;
        ensure!(
            test.width() > 0.0
                && test.height() > 0.0
                && test.x() >= 0.0
                && test.y() > 0.0
                && test.x() + test.width() <= card.child.width() as f32 + 1.0
                && test.y() + test.height() <= card.child.height() as f32 + 1.0,
            "测速按钮不在卡片内"
        );
        ensure!(
            card.child.is_focusable() && card.test.is_focusable(),
            "卡片或测速按钮无法键盘操作"
        );
    }
    fn inspect(widget: &gtk::Widget) -> Result<()> {
        ensure!(
            !widget.is::<gtk::DropDown>()
                && !widget.is::<gtk::SearchEntry>()
                && !widget.is::<gtk::ToggleButton>(),
            "节点页还有分组、搜索或模式选择"
        );
        if let Some(label) = widget.downcast_ref::<gtk::Label>() {
            ensure!(
                ![
                    "代理组",
                    "路由模式",
                    "全局",
                    "规则",
                    "直连",
                    "默认",
                    "代理",
                    "自动选择",
                    "使用"
                ]
                .contains(&label.text().as_str()),
                "节点页显示了内部控制"
            );
        }
        let mut child = widget.first_child();
        while let Some(widget) = child {
            child = widget.next_sibling();
            inspect(&widget)?;
        }
        Ok(())
    }
    inspect(ui.body.upcast_ref())?;
    if let Some(index) = click {
        let child = panel
            .cards
            .borrow()
            .get(index)
            .context("节点索引无效")?
            .child
            .clone();
        panel.grid.emit_by_name::<()>("child-activated", &[&child]);
        let after: Vec<_> = panel
            .data
            .borrow()
            .iter()
            .zip(panel.cards.borrow().iter())
            .filter(|(_, card)| card.child.has_css_class("node-selected"))
            .map(|(n, _)| n.node_tag.clone())
            .collect();
        ensure!(after == highlighted, "选用成功前提前高亮了节点");
    }
    Ok(())
}

/// Exercise the actual icon handler, including its disabled stopped-core guard.
/// The next smoke step checks the selected node after any async work finishes.
pub(super) fn smoke_test_node(ui: &Rc<Ui>, index: usize) -> Result<()> {
    use anyhow::ensure;
    ensure!(ui.jobs.get() == 0, "节点任务未完成");
    let panel = ui.node_panel.borrow().clone().context("节点页未打开")?;
    let before = ui.service.snapshot();
    let node = panel
        .data
        .borrow()
        .get(index)
        .context("节点索引无效")?
        .clone();
    let button = panel
        .cards
        .borrow()
        .get(index)
        .context("缺少节点卡片")?
        .test
        .clone();
    ensure!(
        button.is_sensitive() == node.available,
        "独立测速按钮状态错误"
    );
    button.emit_clicked();
    ensure!(!panel.selecting.get(), "测速图标误触节点选择");
    if node.available {
        ensure!(
            panel.pending.borrow().contains(&node.node_tag),
            "独立测速没有开始"
        );
        ensure!(
            panel.cards.borrow()[index].test_spinner.is_spinning(),
            "独立测速缺少忙状态"
        );
    } else {
        ensure!(
            !panel.pending.borrow().contains(&node.node_tag),
            "未启动内核仍发起了测速"
        );
        ensure!(
            button
                .tooltip_text()
                .is_some_and(|text| text.contains("启动内核")),
            "未说明测速需要启动内核"
        );
    }
    let after = ui.service.snapshot();
    ensure!(
        before.settings.active_subscription == after.settings.active_subscription
            && before.settings.routing_mode == after.settings.routing_mode
            && before
                .subscriptions
                .iter()
                .map(|s| (&s.id, &s.selected_node))
                .eq(after
                    .subscriptions
                    .iter()
                    .map(|s| (&s.id, &s.selected_node))),
        "测速改变了所选节点或模式"
    );
    Ok(())
}
