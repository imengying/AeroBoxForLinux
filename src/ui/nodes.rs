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
    pub(super) fn nodes(self: &Rc<Self>) {
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
        let test = floating_button("aerobox-bolt-symbolic", "测速全部");
        test.set_halign(gtk::Align::End);
        test.set_valign(gtk::Align::End);
        test.set_margin_end(30);
        test.set_margin_bottom(24);
        test.set_widget_name("nodes-test");
        test.set_tooltip_text(Some("测试此订阅的节点延迟"));
        self.floating.add_overlay(&test);
        self.nodes_action.replace(Some(test.clone()));
        reserve_floating_action(&self.body, &test);
        let grid = gtk::FlowBox::new();
        grid.add_css_class("nodes-grid");
        grid.set_hexpand(true);
        grid.set_widget_name("subscription-nodes");
        grid.set_selection_mode(gtk::SelectionMode::None);
        grid.set_activate_on_single_click(true);
        grid.set_homogeneous(true);
        grid.set_min_children_per_line(1);
        grid.set_max_children_per_line(8);
        grid.set_column_spacing(8);
        grid.set_row_spacing(8);
        grid.set_valign(gtk::Align::Start);
        follow_width(&grid, 148, 8, 8, true);
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
    pub(super) fn refresh(self: &Rc<Self>, ui: &Rc<Ui>) {
        self.reload_local(ui);
        self.read_runtime(ui);
    }

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
                child.update_property(&[gtk::accessible::Property::Label(&node.name)]);
                let content = gtk::Box::new(gtk::Orientation::Vertical, 4);
                content.add_css_class("node-card-content");
                let title = gtk::Box::new(gtk::Orientation::Horizontal, 4);
                title.set_vexpand(false);
                let name = label(&node.name, "node-name");
                name.set_hexpand(true);
                name.set_valign(gtk::Align::Start);
                name.set_wrap(false);
                name.set_width_chars(1);
                name.set_max_width_chars(18);
                name.set_ellipsize(gtk::pango::EllipsizeMode::End);
                name.set_tooltip_text(Some(&node.name));
                title.append(&name);
                let indicator = gtk::Stack::new();
                indicator.set_size_request(16, 16);
                indicator.set_valign(gtk::Align::Start);
                indicator.add_named(
                    &gtk::Box::new(gtk::Orientation::Horizontal, 0),
                    Some("empty"),
                );
                let spinner = gtk::Spinner::new();
                indicator.add_named(&spinner, Some("busy"));
                title.append(&indicator);
                content.append(&title);
                let protocol = label(&node.protocol, "muted node-protocol");
                protocol.set_hexpand(true);
                protocol.set_width_chars(1);
                protocol.set_ellipsize(gtk::pango::EllipsizeMode::End);
                let footer = gtk::Box::new(gtk::Orientation::Horizontal, 4);
                footer.add_css_class("node-card-footer");
                footer.append(&protocol);
                let delay = label("", "node-delay");
                delay.set_xalign(1.0);
                let test = gtk::Button::new();
                test.add_css_class("flat");
                test.add_css_class("node-test-button");
                test.set_widget_name("node-test");
                test.set_halign(gtk::Align::End);
                test.set_valign(gtk::Align::Center);
                test.set_tooltip_text(Some("测试此节点延迟"));
                test.update_property(&[gtk::accessible::Property::Label(&format!(
                    "测试 {} 延迟",
                    node.name
                ))]);
                let test_indicator = gtk::Stack::new();
                test_indicator.set_hhomogeneous(false);
                test_indicator.set_size_request(16, 16);
                test_indicator.add_named(&bolt(), Some("icon"));
                test_indicator.add_named(&delay, Some("result"));
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
            card.indicator.set_visible_child_name("empty");
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
            update_delay(card, node.delay_ms);
        }
        drop(previous);
        self.grid.set_visible(!nodes.is_empty());
        self.empty.set_visible(nodes.is_empty());
        self.data.replace(nodes);
        self.controls();
    }

    fn controls(&self) {
        let pending = self.pending.borrow();
        self.test.set_sensitive(
            !self.selecting.get()
                && !self.testing.get()
                && pending.is_empty()
                && !self.data.borrow().is_empty(),
        );
        for (node, card) in self.data.borrow().iter().zip(self.cards.borrow().iter()) {
            let busy = pending.contains(&node.node_tag);
            card.test
                .set_sensitive(!self.selecting.get() && !self.testing.get() && !busy);
            card.test_spinner.set_spinning(busy);
            card.test_indicator.set_visible_child_name(if busy {
                "busy"
            } else if card.delay.text().is_empty() {
                "icon"
            } else {
                "result"
            });
        }
    }

    fn read_runtime(self: &Rc<Self>, ui: &Rc<Ui>) {
        if !ui.service.status().running {
            return;
        }
        let id = self.subscription_id.clone();
        let revision = self.revision.get();
        let generation = ui.service.status().generation;
        let weak = Rc::downgrade(self);
        ui.task_result(
            move |s| s.subscription_nodes(&id),
            move |ui, result| {
                if let Some(panel) = weak.upgrade()
                    && panel.revision.get() == revision
                    && !panel.selecting.get()
                    && panel.pending.borrow().is_empty()
                    && ui.service.status().generation == generation
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
        if node.selected {
            return;
        }
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
                if let Some(panel) = weak.upgrade() {
                    panel.selecting.set(false);
                    let current = ui.page.get() == Page::Nodes
                        && ui
                            .node_panel
                            .borrow()
                            .as_ref()
                            .is_some_and(|current| Rc::ptr_eq(current, &panel));
                    if current {
                        ui.subscription_revision
                            .set(ui.service.subscription_revision());
                        panel.reload_local(ui);
                        panel.read_runtime(ui);
                    }
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
        self.pending.borrow_mut().insert(tag.into());
        self.revision.set(self.revision.get() + 1);
        self.controls();
        let generation = ui.service.status().generation;
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
                if ui.service.status().generation != generation {
                    panel.reload_local(ui);
                    return;
                }
                panel.show_delay(&tag, result);
            },
        );
    }

    fn show_delay(&self, tag: &str, result: Result<u64>) {
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
                    update_delay(card, Some(delay));
                    card.delay.set_tooltip_text(None);
                }
                Err(error) => {
                    node.delay_ms = None;
                    update_delay(card, None);
                    card.delay.set_text("失败");
                    card.test_indicator.set_visible_child_name("result");
                    card.delay.add_css_class("latency-bad");
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
        let generation = ui.service.status().generation;
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
                if ui.service.status().generation != generation {
                    panel.reload_local(ui);
                    return;
                }
                match result {
                    Ok(results) => {
                        for (tag, result) in results {
                            panel.show_delay(&tag, result);
                        }
                    }
                    Err(error) => ui.error("测速失败", error),
                }
            },
        );
    }
}

fn update_delay(card: &NodeCard, delay: Option<u64>) {
    let label = &card.delay;
    label.set_text(&delay_text(delay));
    card.test_indicator
        .set_visible_child_name(if delay.is_some() { "result" } else { "icon" });
    label.remove_css_class("latency-good");
    label.remove_css_class("latency-medium");
    label.remove_css_class("latency-bad");
    if let Some(class) = match delay {
        Some(1..=300) => Some("latency-good"),
        Some(301..=600) => Some("latency-medium"),
        Some(_) => Some("latency-bad"),
        None => None,
    } {
        label.add_css_class(class);
    }
    label.remove_css_class("muted");
}

fn delay_text(delay: Option<u64>) -> String {
    match delay {
        Some(0) => "超时".into(),
        Some(ms) => format!("{ms} ms"),
        None => String::new(),
    }
}

#[cfg(feature = "ui-smoke")]
pub(super) fn smoke_delay_colors(ui: &Rc<Ui>) -> Result<()> {
    use anyhow::ensure;
    let panel = ui.node_panel.borrow().clone().context("节点页未打开")?;
    let cards = panel.cards.borrow();
    ensure!(cards.len() == 2, "延迟配色测试需要两个节点");
    for (card, delay, class) in [
        (&cards[0], Some(180), "latency-good"),
        (&cards[1], Some(420), "latency-medium"),
    ] {
        update_delay(card, delay);
        ensure!(card.delay.has_css_class(class), "延迟没有分级着色");
        ensure!(
            card.test_indicator.visible_child_name().as_deref() == Some("result")
                && card.delay.is_ancestor(&card.test),
            "测速结果没有显示在测试按钮内"
        );
        ensure!(!card.delay.has_css_class("muted"), "延迟仍是次要文字色");
    }
    Ok(())
}

#[cfg(feature = "ui-smoke")]
pub(super) fn smoke_delay_failure(ui: &Rc<Ui>) -> Result<()> {
    use anyhow::ensure;
    let panel = ui.node_panel.borrow().clone().context("节点页未打开")?;
    let cards = panel.cards.borrow();
    for (card, delay, class) in [
        (&cards[0], Some(920), "latency-bad"),
        (&cards[1], Some(0), "latency-bad"),
    ] {
        update_delay(card, delay);
        ensure!(card.delay.has_css_class(class), "高延迟或超时没有警示色");
    }
    Ok(())
}

#[cfg(feature = "ui-smoke")]
pub(super) fn smoke_floating_action(ui: &Rc<Ui>) -> Result<()> {
    use anyhow::ensure;
    let panel = ui.node_panel.borrow().clone().context("节点页未打开")?;
    let action = ui.nodes_action.borrow().clone().context("缺少悬浮测速")?;
    ensure!(
        !descendants(&action)
            .iter()
            .any(|widget| widget.is::<gtk::Label>()),
        "悬浮测速应只显示图标"
    );
    ensure!(
        action.has_css_class("secondary-action") && !action.has_css_class("suggested-action"),
        "测速全部不应与启动争夺主操作层级"
    );
    let font_px = action
        .pango_context()
        .font_description()
        .map(|font| font.size() as f32 / gtk::pango::SCALE as f32 * 96.0 / 72.0)
        .unwrap_or(14.7);
    ensure!(
        action.height() as f32 >= 28.0
            && (action.height() as f32) < font_px * 3.6
            && (action.width() - action.height()).abs() <= 1,
        "测速按钮没有按字号保持紧凑: {}x{}, font={font_px}",
        action.width(),
        action.height()
    );
    ensure!(
        action.halign() == gtk::Align::End && action.valign() == gtk::Align::End,
        "测速不在右下角"
    );
    let action_bounds = action
        .compute_bounds(&ui.floating)
        .context("悬浮测速没有位置")?;
    let hit = ui
        .floating
        .pick(
            f64::from(action_bounds.x() / 2.0),
            f64::from(action_bounds.y() + action_bounds.height() / 2.0),
            gtk::PickFlags::DEFAULT,
        )
        .context("悬浮测速旁的列表无法操作")?;
    ensure!(
        hit == *ui.scroll.upcast_ref::<gtk::Widget>() || hit.is_ancestor(&ui.scroll),
        "测速按钮占用了列表底部一整行"
    );
    if let Some(card) = panel.cards.borrow().last() {
        let card_bounds = card
            .child
            .compute_bounds(&ui.floating)
            .context("末尾节点没有位置")?;
        let overlap_x = card_bounds.x() < action_bounds.x() + action_bounds.width()
            && action_bounds.x() < card_bounds.x() + card_bounds.width();
        let overlap_y = card_bounds.y() < action_bounds.y() + action_bounds.height()
            && action_bounds.y() < card_bounds.y() + card_bounds.height();
        ensure!(
            !(overlap_x && overlap_y),
            "滚到底后测速按钮仍遮挡最后一张卡片: card=({},{},{}x{}) action=({},{},{}x{})",
            card_bounds.x(),
            card_bounds.y(),
            card_bounds.width(),
            card_bounds.height(),
            action_bounds.x(),
            action_bounds.y(),
            action_bounds.width(),
            action_bounds.height()
        );
    }
    Ok(())
}

#[cfg(feature = "ui-smoke")]
pub(super) fn smoke_fullscreen(ui: &Rc<Ui>) -> Result<()> {
    use anyhow::ensure;
    ensure!(ui.window.is_fullscreen(), "节点窗口未进入全屏");
    let expected = if ui.window.width() >= 1800 { 120 } else { 112 };
    ensure!(
        ui.scroll.width() >= 1000 && ui.typography.density_percent() == expected,
        "全屏内容区或密度尚未应用: viewport={}x{} density={}%",
        ui.scroll.width(),
        ui.scroll.height(),
        ui.typography.density_percent()
    );
    ensure!(ui.typography.preview() == 11, "全屏不应改写用户字号");
    ensure!(
        ui.content_clamp.maximum_size() > 1030,
        "全屏内容仍被旧限宽约束"
    );
    ensure!(
        ui.split.min_sidebar_width() > 128.0,
        "全屏侧栏没有跟随整体密度"
    );
    let panel = ui.node_panel.borrow().clone().context("节点页未打开")?;
    let cards = panel.cards.borrow();
    let first_y = cards[0].child.allocation().y();
    let columns = cards
        .iter()
        .take_while(|card| card.child.allocation().y() == first_y)
        .count();
    ensure!(columns > 3, "全屏节点没有扩展列数: {columns}");
    ensure!(
        cards.iter().all(|card| {
            card.child.width() > 148
                && card.child.width() < 330
                && card.test.width() >= 28
                && card.test.height() >= 28
        }),
        "全屏卡片或测速命中区尺寸不合理"
    );
    Ok(())
}

#[cfg(feature = "ui-smoke")]
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
    let cards = panel.cards.borrow();
    if count >= 5 && ui.window.width() == 1000 && ui.typography.preview() == 11 {
        let first_y = cards[0].child.allocation().y();
        let first_row = cards
            .iter()
            .take_while(|card| card.child.allocation().y() == first_y)
            .count();
        ensure!(
            first_row == 4,
            "常规窗口第一行显示了 {first_row} 个节点: grid={} max={}",
            panel.grid.width(),
            panel.grid.max_children_per_line()
        );
    }
    for card in cards.iter() {
        ensure!(
            !descendants(&card.child).iter().any(|widget| widget
                .downcast_ref::<gtk::Label>()
                .is_some_and(|label| label.text() == "未测速")),
            "未测速节点仍显示占位说明"
        );
        ensure!(
            !descendants(&card.child)
                .iter()
                .filter_map(|widget| widget.downcast_ref::<gtk::Image>())
                .any(|image| image.icon_name().as_deref() == Some("object-select-symbolic")),
            "节点卡片仍显示选中角标"
        );
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
            test.width() >= 28.0
                && test.height() >= 28.0
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

#[cfg(feature = "ui-smoke")]
pub(super) async fn smoke_selection_navigation(ui: &Rc<Ui>) -> Result<()> {
    use anyhow::ensure;
    ensure!(ui.jobs.get() == 0, "节点任务未完成");
    ensure!(!ui.service.status().running, "切页自检不能更改运行中的节点");
    let panel = ui.node_panel.borrow().clone().context("节点页未打开")?;
    let (original, index, selected) = {
        let data = panel.data.borrow();
        let original = data
            .iter()
            .find(|node| node.selected)
            .context("缺少原选中节点")?
            .node_tag
            .clone();
        let index = data
            .iter()
            .position(|node| !node.selected)
            .context("切页自检至少需要两个节点")?;
        (original, index, data[index].node_tag.clone())
    };

    let revision = ui.service.subscription_revision();
    ui.subscription_revision.set(revision);
    // Keep an unrelated real task pending so the heartbeat cannot consume the
    // revision before this test observes the selection callback's result.
    let (release, blocked) = mpsc::channel();
    ui.task_result(
        move |_| blocked.recv().context("节点切页自检任务未释放"),
        |_, _| {},
    );
    let child = panel.cards.borrow()[index].child.clone();
    panel.grid.emit_by_name::<()>("child-activated", &[&child]);
    ensure!(panel.selecting.get(), "节点选择没有启动");
    ui.navigate(Page::Subscriptions);
    ui.navigate(Page::Nodes);
    let returned = ui.node_panel.borrow().clone().context("没有返回节点页")?;
    let returned_revision = ui.subscription_revision.get();
    ensure!(!Rc::ptr_eq(&panel, &returned), "返回节点页仍在使用旧控制器");

    // Retain the old panel deliberately: checking only Weak::upgrade or the
    // current page is insufficient after navigating away and straight back.
    let start = std::time::Instant::now();
    while panel.selecting.get() {
        ensure!(start.elapsed() < Duration::from_secs(5), "节点选择没有完成");
        glib::timeout_future(Duration::from_millis(16)).await;
    }
    ensure!(
        ui.service
            .subscription_nodes(&panel.subscription_id)?
            .iter()
            .any(|node| node.selected && node.node_tag == selected),
        "切页期间没有保存所选节点"
    );
    ensure!(
        ui.service.subscription_revision() > revision
            && ui.subscription_revision.get() == returned_revision,
        "旧节点页吞掉了当前页面尚未处理的变更"
    );
    let needs_refresh = returned_revision != ui.service.subscription_revision();
    release.send(())?;
    let start = std::time::Instant::now();
    while ui.jobs.get() > 0 || ui.subscription_revision.get() != ui.service.subscription_revision()
    {
        ensure!(
            start.elapsed() < Duration::from_secs(5),
            "节点页没有处理待刷新变更"
        );
        glib::timeout_future(Duration::from_millis(16)).await;
    }
    // The selection may have committed before the returned page was built.
    // Give the heartbeat a turn and ensure it preserves that up-to-date page.
    if !needs_refresh {
        glib::timeout_future(Duration::from_millis(1100)).await;
    }
    let current = ui.node_panel.borrow().clone().context("节点页已丢失")?;
    ensure!(
        Rc::ptr_eq(&returned, &current) != needs_refresh,
        "节点页遗漏了待刷新变更或重复刷新了已显示的变更"
    );
    ensure!(
        current
            .data
            .borrow()
            .iter()
            .zip(current.cards.borrow().iter())
            .filter(|(_, card)| card.child.has_css_class("node-selected"))
            .map(|(node, _)| node.node_tag.as_str())
            .eq([selected.as_str()]),
        "返回节点页后高亮仍是旧节点"
    );

    let index = current
        .data
        .borrow()
        .iter()
        .position(|node| node.node_tag == original)
        .context("原节点已丢失")?;
    let child = current.cards.borrow()[index].child.clone();
    current
        .grid
        .emit_by_name::<()>("child-activated", &[&child]);
    let start = std::time::Instant::now();
    while ui.jobs.get() > 0 {
        ensure!(start.elapsed() < Duration::from_secs(5), "原节点未恢复");
        glib::timeout_future(Duration::from_millis(16)).await;
    }
    ensure!(
        current
            .data
            .borrow()
            .iter()
            .any(|node| node.selected && node.node_tag == original)
            && ui.subscription_revision.get() == ui.service.subscription_revision(),
        "当前节点页没有就地更新恢复选择"
    );
    Ok(())
}

/// Exercise stopped-state testing without changing selection or starting a listener.
#[cfg(feature = "ui-smoke")]
pub(super) async fn smoke_test_node(ui: &Rc<Ui>, index: usize) -> Result<()> {
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
    let generation = ui.service.status().generation;
    ensure!(button.is_sensitive(), "停止状态不能测速");
    button.emit_clicked();
    ensure!(!panel.selecting.get(), "测速图标误触节点选择");
    ensure!(
        panel.pending.borrow().contains(&node.node_tag),
        "独立测速没有开始"
    );
    ensure!(
        panel.cards.borrow()[index].test_spinner.is_spinning(),
        "独立测速缺少忙状态"
    );
    let began = std::time::Instant::now();
    while ui.jobs.get() > 0 {
        ensure!(began.elapsed() < Duration::from_secs(10), "节点测速未结束");
        glib::timeout_future(Duration::from_millis(20)).await;
    }
    ensure!(
        ui.service.status().generation == generation,
        "测速启动了连接"
    );
    ensure!(button.is_sensitive(), "测速结束后按钮未恢复");
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
