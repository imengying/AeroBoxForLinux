use super::*;
use aerobox_for_linux::traffic::{Counters, RateMeter};
use std::time::Instant;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct ExitIpKey {
    generation: Option<u64>,
    subscription: String,
    node: Option<String>,
    mode: String,
    ipv6: bool,
}

pub(super) struct Dashboard {
    controls: gtk::Box,
    modes: Vec<(&'static str, gtk::ToggleButton)>,
    switches: Vec<(bool, gtk::Switch)>,
    syncing: Rc<Cell<bool>>,
    running: Cell<bool>,
    exit_key: RefCell<ExitIpKey>,
    download: gtk::Label,
    upload: gtk::Label,
    download_unit: gtk::Label,
    upload_unit: gtk::Label,
    download_total: gtk::Label,
    upload_total: gtk::Label,
    connections: gtk::Label,
    uptime: gtk::Label,
    memory: gtk::Label,
    exit_ip: gtk::Label,
    network: gtk::Button,
    rates: RefCell<RateMeter>,
    pending: Cell<bool>,
    memory_at: Cell<Option<Instant>>,
}

impl Ui {
    pub(super) fn home(self: &Rc<Self>) {
        self.body.add_css_class("home-page");
        self.body.set_spacing(16);
        // The start button is an overlay, not a toolbar. Reserve room for it
        // inside the scrolling content so it never carves a blank strip off
        // the page; the card list simply ends above the button when scrolled
        // to the bottom.
        self.body.set_margin_bottom(84);
        let state = self.service.snapshot();
        let status = self.service.status();
        let syncing = Rc::new(Cell::new(false));

        let toggle = primary(
            if status.running { "停止" } else { "启动" },
            if status.running {
                "media-playback-stop-symbolic"
            } else {
                "media-playback-start-symbolic"
            },
        );
        toggle.add_css_class("floating-action");
        toggle.set_widget_name("home-start");
        toggle.set_halign(gtk::Align::End);
        toggle.set_valign(gtk::Align::End);
        toggle.set_margin_end(30);
        toggle.set_margin_bottom(24);
        if status.running {
            toggle.remove_css_class("suggested-action");
            toggle.add_css_class("destructive-action");
        }
        toggle.set_sensitive(
            status.running
                || (self.jobs.get() == 0
                    && state.subscriptions.iter().any(|sub| {
                        sub.id == state.settings.active_subscription
                            && model::has_selectable_node(&sub.nodes)
                    })),
        );
        let weak = Rc::downgrade(self);
        toggle.connect_clicked(move |button| {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let running = ui.service.status().running;
            if ui.jobs.get() > 0 && !running {
                return;
            }
            ui.button_task(
                button,
                if running {
                    "停止中…"
                } else {
                    "启动中…"
                },
                move |s| if running { s.stop() } else { s.start() },
                |ui, result| {
                    ui.refresh(Page::Home);
                    if let Err(e) = result {
                        ui.error("操作失败", format!("{e:#}"));
                    }
                },
            );
            ui.refresh(Page::Home);
        });
        self.floating.add_overlay(&toggle);
        self.home_action.replace(Some(toggle));

        let top = flow(1, 2);
        follow_width(&top, 232, 14, 2, false);
        top.set_vexpand(false);
        top.add_css_class("home-top");
        let network = gtk::Button::new();
        network.add_css_class("surface-card");
        network.add_css_class("home-network");
        network.set_widget_name("exit-ip");
        network.set_tooltip_text(Some("点击检测出口 IP"));
        network.update_property(&[gtk::accessible::Property::Label("检测出口 IP")]);
        let content = gtk::Box::new(gtk::Orientation::Vertical, 8);
        let header = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        header.append(&gtk::Image::from_icon_name("network-wireless-symbolic"));
        header.append(&label("出口 IP", "section-title"));
        content.append(&header);
        let exit_ip = label("—", "exit-ip");
        exit_ip.set_hexpand(true);
        exit_ip.set_wrap(true);
        exit_ip.set_wrap_mode(gtk::pango::WrapMode::Char);
        exit_ip.set_width_chars(1);
        exit_ip.set_max_width_chars(39);
        content.append(&exit_ip);
        network.set_child(Some(&content));
        top.insert(&network, -1);

        let speeds = gtk::Box::new(gtk::Orientation::Horizontal, 14);
        speeds.set_homogeneous(true);
        let (down, download, download_unit, download_total) =
            speed_card("go-down-symbolic", "下载", "download");
        let (up, upload, upload_unit, upload_total) =
            speed_card("go-up-symbolic", "上传", "upload");
        speeds.append(&up);
        speeds.append(&down);
        top.insert(&speeds, -1);
        self.body.append(&top);

        let controls = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let control_grid = flow(1, 2);
        follow_width(&control_grid, 232, 14, 2, false);
        let mode_row = card(gtk::Orientation::Vertical, 12);
        mode_row.add_css_class("home-mode");
        let mode_header = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let title = label("出站模式", "section-title");
        title.set_hexpand(true);
        mode_header.append(&title);
        let mode_spinner = gtk::Spinner::new();
        mode_spinner.set_size_request(18, 18);
        mode_spinner.set_opacity(0.0);
        mode_header.append(&mode_spinner);
        mode_row.append(&mode_header);
        let modes = gtk::Box::new(gtk::Orientation::Horizontal, 4);
        modes.set_homogeneous(true);
        modes.add_css_class("mode-selector");
        let mut first: Option<gtk::ToggleButton> = None;
        let mut mode_buttons = Vec::new();
        for (title, value) in [("规则", "rule"), ("全局", "global"), ("直连", "direct")] {
            let button = gtk::ToggleButton::with_label(title);
            if let Some(first) = &first {
                button.set_group(Some(first));
            } else {
                first = Some(button.clone());
            }
            button.set_active(state.settings.routing_mode == value);
            let weak = Rc::downgrade(self);
            let syncing = syncing.clone();
            let spinner = mode_spinner.clone();
            button.connect_toggled(move |button| {
                if syncing.get() || !button.is_active() {
                    return;
                }
                if let Some(ui) = weak.upgrade()
                    && ui.jobs.get() == 0
                {
                    spinner.set_opacity(1.0);
                    spinner.start();
                    let spinner = spinner.clone();
                    ui.task_result(
                        move |s| s.set_routing_mode(value),
                        move |ui, result| {
                            spinner.stop();
                            spinner.set_opacity(0.0);
                            ui.refresh(Page::Home);
                            if let Err(e) = result {
                                ui.error("切换失败", format!("{e:#}"));
                            }
                        },
                    );
                    ui.refresh(Page::Home);
                }
            });
            modes.append(&button);
            mode_buttons.push((value, button));
        }
        mode_row.append(&modes);
        control_grid.insert(&mode_row, -1);

        let switches = card(gtk::Orientation::Vertical, 0);
        switches.add_css_class("home-takeover");
        let mut switch_controls = Vec::new();
        for (title, system, active, icon) in [
            (
                "系统代理",
                true,
                if status.running {
                    status.proxy
                } else {
                    state.settings.system_proxy
                },
                "network-workgroup-symbolic",
            ),
            (
                "虚拟网卡",
                false,
                state.settings.tun_enabled,
                "network-wired-symbolic",
            ),
        ] {
            let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
            row.add_css_class("home-switch");
            let image = gtk::Image::from_icon_name(icon);
            image.add_css_class("muted");
            row.append(&image);
            let name = label(title, "section-title");
            name.set_hexpand(true);
            row.append(&name);
            let switch = gtk::Switch::new();
            switch.set_valign(gtk::Align::Center);
            switch.set_active(active);
            switch.set_widget_name(if system { "system-proxy" } else { "tun" });
            switch.update_property(&[gtk::accessible::Property::Label(title)]);
            let weak = Rc::downgrade(self);
            let syncing = syncing.clone();
            switch.connect_state_set(move |_, enabled| {
                if syncing.get() {
                    return glib::Propagation::Proceed;
                }
                if let Some(ui) = weak.upgrade()
                    && ui.jobs.get() == 0
                {
                    ui.task_result(
                        move |s| {
                            if system {
                                s.set_system_proxy_enabled(enabled)
                            } else {
                                let mut settings = s.snapshot().settings;
                                settings.tun_enabled = enabled;
                                s.apply_settings(settings)
                            }
                        },
                        |ui, result| {
                            ui.refresh(Page::Home);
                            if let Err(e) = result {
                                ui.error("设置失败", format!("{e:#}"));
                            }
                        },
                    );
                    ui.refresh(Page::Home);
                }
                glib::Propagation::Stop
            });
            row.append(&switch);
            switches.append(&row);
            switch_controls.push((system, switch));
        }
        control_grid.insert(&switches, -1);
        controls.append(&control_grid);
        self.body.append(&controls);

        let stats = flow(1, 3);
        // Three equal cards only while they stay readable; narrow windows drop
        // to two or one instead of squeezing the labels.
        follow_width(&stats, 168, 14, 3, false);
        stats.add_css_class("home-stats");
        let (connection_box, connections) = stat("network-workgroup-symbolic", "连接数", "—");
        let (uptime_box, uptime) = stat(
            "preferences-system-time-symbolic",
            "运行时间",
            &duration(status.uptime),
        );
        let (memory_box, memory) = stat("computer-symbolic", "内存占用", "—");
        stats.insert(&connection_box, -1);
        stats.insert(&uptime_box, -1);
        stats.insert(&memory_box, -1);
        self.body.append(&stats);

        let dashboard = Rc::new(Dashboard {
            modes: mode_buttons,
            controls,
            switches: switch_controls,
            syncing,
            running: Cell::new(status.running),
            exit_key: RefCell::new(self.detect_key()),
            download,
            upload,
            download_unit,
            upload_unit,
            download_total,
            upload_total,
            connections,
            uptime,
            memory,
            exit_ip,
            network: network.clone(),
            rates: RefCell::new(RateMeter::default()),
            pending: Cell::new(false),
            memory_at: Cell::new(None),
        });
        let weak = Rc::downgrade(self);
        let weak_dashboard = Rc::downgrade(&dashboard);
        network.connect_clicked(move |_| {
            if let (Some(ui), Some(dashboard)) = (weak.upgrade(), weak_dashboard.upgrade()) {
                dashboard.detect(&ui, ui.detect_key());
            }
        });
        dashboard.tick(self);
        self.dashboard.replace(Some(dashboard.clone()));
        let key = self.detect_key();
        if self.detecting.borrow().as_ref() == Some(&key) {
            dashboard.show_detecting();
        } else if let Some((_, info)) = self
            .last_detected
            .borrow()
            .as_ref()
            .filter(|(cached, _)| cached == &key)
        {
            dashboard.show_info(info);
        } else if state.settings.auto_detect_ip {
            dashboard.detect(self, key);
        }
    }
}

impl Ui {
    fn detect_key(&self) -> ExitIpKey {
        let state = self.service.snapshot();
        let status = self.service.status();
        let node = state
            .subscriptions
            .iter()
            .find(|sub| sub.id == state.settings.active_subscription)
            .and_then(|sub| sub.selected_node.clone());
        ExitIpKey {
            generation: status.generation,
            subscription: state.settings.active_subscription,
            node,
            mode: state.settings.routing_mode,
            ipv6: state.settings.ipv6,
        }
    }
}

pub(super) fn smoke_cards(ui: &Rc<Ui>) -> Result<()> {
    let cards = descendants(&ui.body)
        .into_iter()
        .filter(|widget| {
            matches!(
                widget.widget_name().as_str(),
                "exit-ip" | "upload" | "download"
            )
        })
        .map(|widget| widget.compute_bounds(&ui.body).context("首页卡片没有位置"))
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(cards.len() == 3, "首页缺少出口 IP 或流量卡片");
    anyhow::ensure!(
        cards.iter().all(
            |bounds| bounds.height() > 0.0 && (bounds.height() - cards[0].height()).abs() < 1.0
        ),
        "出口 IP、上传、下载卡片高度不一致"
    );
    anyhow::ensure!(
        cards.iter().all(|bounds| bounds.x() >= -1.0
            && bounds.x() + bounds.width() <= ui.body.width() as f32 + 1.0)
            && cards[1].x() < cards[2].x(),
        "首页卡片被裁切或上传、下载顺序错误"
    );
    let dashboard = ui.dashboard.borrow().clone().context("缺少首页")?;
    let text = dashboard.exit_ip.layout().pixel_size();
    anyhow::ensure!(
        text.0 <= dashboard.exit_ip.width() && text.1 <= dashboard.exit_ip.height(),
        "出口 IP 内容被裁切"
    );
    Ok(())
}

pub(super) async fn smoke_controls(ui: &Rc<Ui>) -> Result<()> {
    let dashboard = ui.dashboard.borrow().clone().context("缺少首页")?;
    let content = ui.body.first_child().context("首页没有内容")?;
    let scroll = ui.scroll.vadjustment().value();
    for mode in ["global", "direct", "rule"] {
        let button = dashboard
            .modes
            .iter()
            .find(|(value, _)| *value == mode)
            .unwrap()
            .1
            .clone();
        let label = button.label();
        button.emit_clicked();
        let started = Instant::now();
        while ui.jobs.get() > 0 {
            anyhow::ensure!(started.elapsed() < Duration::from_secs(5), "切换模式未完成");
            glib::timeout_future(Duration::from_millis(16)).await;
        }
        anyhow::ensure!(
            ui.service.snapshot().settings.routing_mode == mode
                && button.is_active()
                && button.label() == label
                && ui
                    .dashboard
                    .borrow()
                    .as_ref()
                    .is_some_and(|current| Rc::ptr_eq(current, &dashboard))
                && ui.body.first_child().as_ref() == Some(&content)
                && ui.scroll.vadjustment().value() == scroll,
            "切换模式重建了首页、改变了布局或未完成切换"
        );
        button.emit_clicked();
        anyhow::ensure!(ui.jobs.get() == 0, "点击当前模式重复发起切换");
    }
    for (system, switch) in &dashboard.switches {
        let original = switch.is_active();
        for active in [!original, original] {
            switch.set_active(active);
            let started = Instant::now();
            while ui.jobs.get() > 0 {
                anyhow::ensure!(
                    started.elapsed() < Duration::from_secs(5),
                    "更新首页开关未完成"
                );
                glib::timeout_future(Duration::from_millis(16)).await;
            }
            let settings = ui.service.snapshot().settings;
            let saved = if *system {
                settings.system_proxy
            } else {
                settings.tun_enabled
            };
            anyhow::ensure!(
                saved == active
                    && switch.state() == active
                    && switch.is_active() == active
                    && ui.body.first_child().as_ref() == Some(&content),
                "更新首页开关后状态错误或页面被重建"
            );
        }
    }
    // A selection can finish after the user has already returned home.
    // Neither switching a stopped subscription nor a hot node switch changes
    // the runtime generation; the dashboard must still invalidate the old IP.
    let state = ui.service.snapshot();
    let active = state
        .subscriptions
        .iter()
        .find(|sub| sub.id == state.settings.active_subscription)
        .context("缺少当前订阅")?;
    let original = active.selected_node.as_deref().context("缺少选中节点")?;
    let alternate = model::selectable_nodes(&active.nodes)
        .filter_map(|node| node["tag"].as_str())
        .find(|tag| *tag != original)
        .context("缺少备用节点")?;
    let other = state
        .subscriptions
        .iter()
        .find(|sub| sub.id != active.id)
        .context("缺少备用订阅")?;
    let generation = ui.service.status().generation;
    let reading = network::NetworkInfo {
        ipv4: Some("192.0.2.10".into()),
        ..Default::default()
    };
    for subscription in [false, true] {
        dashboard.show_info(&reading);
        if subscription {
            ui.service.select_subscription(&other.id)?;
        } else {
            ui.service.select_subscription_node(&active.id, alternate)?;
        }
        dashboard.tick(ui);
        anyhow::ensure!(
            ui.service.status().generation == generation
                && *dashboard.exit_key.borrow() == ui.detect_key()
                && dashboard.exit_ip.text() == "—"
                && dashboard.network.is_sensitive()
                && ui.body.first_child().as_ref() == Some(&content),
            "切换节点或订阅后首页仍显示旧出口 IP，或重建了页面"
        );
        ui.service.select_subscription_node(&active.id, original)?;
        dashboard.tick(ui);
    }
    let ipv6_reading = network::NetworkInfo {
        ipv6: Some("2001:db8::10".into()),
        ..Default::default()
    };
    for enabled in [!state.settings.ipv6, state.settings.ipv6] {
        ui.service.update(|state| {
            state.settings.ipv6 = enabled;
            Ok(())
        })?;
        dashboard.tick(ui);
        dashboard.show_info(&ipv6_reading);
        anyhow::ensure!(
            dashboard.exit_ip.text() == if enabled { "2001:db8::10" } else { "不可用" },
            "首页仍使用旧的 IPv6 设置"
        );
    }
    dashboard.exit_ip.set_text("—");
    Ok(())
}

pub(super) async fn smoke_ip_cache(ui: &Rc<Ui>) -> Result<()> {
    let before = ui.detect_count.get();
    let ipv6 = ui.service.snapshot().settings.ipv6;
    ui.service.update(|state| {
        state.settings.auto_detect_ip = true;
        Ok(())
    })?;
    // Seed a known reading so this check never depends on a public IP service.
    ui.last_detected.replace(Some((
        ui.detect_key(),
        network::NetworkInfo {
            ipv4: Some("192.0.2.10".into()),
            ipv6: Some("2001:db8:abcd:1234:5678:9abc:def0:1234".into()),
            ..Default::default()
        },
    )));
    ui.navigate(Page::Home);
    let dashboard = ui.dashboard.borrow().clone().context("缺少首页")?;
    anyhow::ensure!(
        dashboard.exit_ip.text() == "192.0.2.10" && ui.detect_count.get() == before,
        "返回首页时未优先显示缓存的 IPv4"
    );
    let info = network::NetworkInfo {
        ipv6: Some("2001:db8:abcd:1234:5678:9abc:def0:1234".into()),
        ..Default::default()
    };
    dashboard.show_info(&info);
    anyhow::ensure!(
        dashboard.exit_ip.text() == info.ipv6.as_deref().filter(|_| ipv6).unwrap_or("不可用"),
        "出口 IP 未按 IPv6 开关回退显示"
    );
    glib::timeout_future(Duration::from_millis(100)).await;
    smoke_cards(ui)?;
    let bounds = dashboard
        .network
        .compute_bounds(&ui.window)
        .context("出口 IP 卡片没有位置")?;
    let hit = ui
        .window
        .pick(
            f64::from(bounds.x() + bounds.width() / 2.0),
            f64::from(bounds.y() + bounds.height() / 2.0),
            gtk::PickFlags::DEFAULT,
        )
        .context("出口 IP 卡片无法点击")?;
    anyhow::ensure!(
        dashboard.network.is_mapped()
            && dashboard.network.is_sensitive()
            && dashboard.network.is_focusable()
            && (hit == *dashboard.network.upcast_ref::<gtk::Widget>()
                || hit.is_ancestor(&dashboard.network)),
        "出口 IP 卡片无法整卡操作"
    );
    dashboard.network.emit_clicked();
    anyhow::ensure!(
        ui.detect_count.get() == before + 1
            && !dashboard.network.is_sensitive()
            && dashboard.exit_ip.text() == "检测中…",
        "点击出口 IP 卡片未重新检测"
    );
    dashboard.network.emit_clicked();
    anyhow::ensure!(
        ui.detect_count.get() == before + 1,
        "重复点击发起了重复检测"
    );
    ui.navigate(Page::Connections);
    ui.navigate(Page::Home);
    anyhow::ensure!(ui.detect_count.get() == before + 1, "返回首页重复发起检测");
    ui.navigate(Page::Connections);
    ui.service.update(|state| {
        state.settings.ipv6 = !ipv6;
        Ok(())
    })?;
    ui.navigate(Page::Home);
    anyhow::ensure!(ui.detect_count.get() == before + 2, "IPv6 改变后未重新检测");
    ui.navigate(Page::Connections);
    ui.navigate(Page::Home);
    let dashboard = ui.dashboard.borrow().clone().context("缺少首页")?;
    anyhow::ensure!(
        ui.detect_count.get() == before + 2 && !dashboard.network.is_sensitive(),
        "切换页面后没有复用正在进行的检测"
    );
    ui.navigate(Page::Connections);
    ui.service.update(|state| {
        state.settings.auto_detect_ip = false;
        state.settings.ipv6 = ipv6;
        Ok(())
    })?;
    // The following narrow-window checks exercise a full-length IPv6 address.
    ui.last_detected.replace(Some((ui.detect_key(), info)));
    Ok(())
}

impl Dashboard {
    pub(super) fn refresh(self: &Rc<Self>, ui: &Rc<Ui>) {
        self.controls.set_sensitive(ui.jobs.get() == 0);
        let state = ui.service.snapshot();
        let status = ui.service.status();
        if self.running.replace(status.running) != status.running
            && let Some(button) = ui.home_action.borrow().as_ref()
        {
            let content = gtk::Box::new(gtk::Orientation::Horizontal, 7);
            content.append(&gtk::Image::from_icon_name(if status.running {
                "media-playback-stop-symbolic"
            } else {
                "media-playback-start-symbolic"
            }));
            content.append(&label(if status.running { "停止" } else { "启动" }, ""));
            button.set_child(Some(&content));
            // A running child can be stopped while startup waits for rules or API readiness.
            button.set_sensitive(status.running);
            for (class, active) in [
                ("suggested-action", !status.running),
                ("destructive-action", status.running),
            ] {
                if active {
                    button.add_css_class(class);
                } else {
                    button.remove_css_class(class);
                }
            }
        }
        if ui.jobs.get() > 0 {
            return;
        }
        self.syncing.set(true);
        for (value, button) in &self.modes {
            button.set_active(*value == state.settings.routing_mode);
        }
        for (system, switch) in &self.switches {
            let active = if *system {
                if status.running {
                    status.proxy
                } else {
                    state.settings.system_proxy
                }
            } else {
                state.settings.tun_enabled
            };
            switch.set_state(active);
            switch.set_active(active);
        }
        self.syncing.set(false);
        let key = ui.detect_key();
        let before = self.exit_key.replace(key.clone());
        if before.generation != key.generation {
            self.unavailable("");
        }
        if before != key {
            if state.settings.auto_detect_ip {
                self.detect(ui, key);
            } else {
                self.exit_ip.set_text("—");
                self.network.set_sensitive(true);
                self.network.set_tooltip_text(Some("点击检测出口 IP"));
                self.network
                    .update_property(&[gtk::accessible::Property::Label("检测出口 IP")]);
            }
        }
    }

    pub(super) fn tick(self: &Rc<Self>, ui: &Rc<Ui>) {
        let status = ui.service.status();
        if ui.jobs.get() == 0 && *self.exit_key.borrow() != ui.detect_key() {
            self.refresh(ui);
        }
        self.controls.set_sensitive(ui.jobs.get() == 0);
        if let Some(button) = ui.home_action.borrow().as_ref() {
            if ui.jobs.get() == 0 {
                let state = ui.service.snapshot();
                button.set_sensitive(
                    status.running
                        || state.subscriptions.iter().any(|sub| {
                            sub.id == state.settings.active_subscription
                                && model::has_selectable_node(&sub.nodes)
                        }),
                );
            } else if !status.running {
                button.set_sensitive(false);
            }
        }
        self.uptime.set_text(&duration(status.uptime));
        let memory_due = self
            .memory_at
            .get()
            .is_none_or(|at| at.elapsed() >= Duration::from_secs(2));
        if (!status.running && !memory_due) || self.pending.replace(true) {
            return;
        }
        if memory_due {
            self.memory_at.set(Some(Instant::now()));
        }
        let running = status.running;
        let saved_mode = ui.service.snapshot().settings.routing_mode;
        let (tx, rx) = mpsc::channel();
        let service = ui.service.clone();
        std::thread::spawn(move || {
            let memory = memory_due.then(|| service.memory_usage());
            let traffic = running.then(|| service.traffic());
            let mode = service.runtime_mode();
            let _ = tx.send((Instant::now(), memory, traffic, mode));
        });
        let weak = Rc::downgrade(self);
        let weak_ui = Rc::downgrade(ui);
        glib::timeout_add_local(Duration::from_millis(50), move || {
            let (Some(dashboard), Some(ui)) = (weak.upgrade(), weak_ui.upgrade()) else {
                return glib::ControlFlow::Break;
            };
            match rx.try_recv() {
                Ok((at, memory, traffic, mode)) => {
                    dashboard.pending.set(false);
                    if ui.service.status().generation == status.generation {
                        if ui.jobs.get() == 0
                            && ui.service.snapshot().settings.routing_mode == saved_mode
                            && let Ok(mode) = mode
                        {
                            dashboard.syncing.set(true);
                            for (value, button) in &dashboard.modes {
                                if *value == mode {
                                    button.set_active(true);
                                }
                            }
                            dashboard.syncing.set(false);
                        }
                        if let Some(memory) = memory {
                            dashboard.memory.set_text(
                                &memory.total_bytes.map(bytes).unwrap_or_else(|| "—".into()),
                            );
                            dashboard.memory.set_tooltip_text(Some(&format!(
                                "AeroBox 整体内存（{}）",
                                memory.basis.label()
                            )));
                        }
                        if let Some(result) = traffic {
                            match result {
                                Ok(counters) => dashboard.update(at, counters),
                                Err(e) => dashboard.unavailable(&format!("{e:#}")),
                            }
                        }
                    }
                    glib::ControlFlow::Break
                }
                Err(mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                Err(mpsc::TryRecvError::Disconnected) => {
                    dashboard.pending.set(false);
                    dashboard.unavailable("统计读取失败");
                    glib::ControlFlow::Break
                }
            }
        });
    }
    fn show_info(&self, info: &aerobox_for_linux::network::NetworkInfo) {
        let ip = info
            .ipv4
            .as_deref()
            .or_else(|| info.ipv6.as_deref().filter(|_| self.exit_key.borrow().ipv6))
            .unwrap_or("不可用");
        self.exit_ip.set_text(ip);
        self.network.set_tooltip_text(Some("点击检测出口 IP"));
        self.network
            .update_property(&[gtk::accessible::Property::Label(&format!(
                "出口 IP {ip}，点击重新检测"
            ))]);
    }

    fn show_detecting(&self) {
        self.network.set_sensitive(false);
        self.exit_ip.set_text("检测中…");
        self.network.set_tooltip_text(None);
        self.network
            .update_property(&[gtk::accessible::Property::Label("正在检测出口 IP")]);
    }

    fn detect(&self, ui: &Rc<Ui>, key: ExitIpKey) {
        self.show_detecting();
        if ui.detecting.borrow().as_ref() == Some(&key) {
            return;
        }
        ui.detecting.replace(Some(key.clone()));
        let request = ui.detect_count.get() + 1;
        ui.detect_count.set(request);
        let service = ui.service.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(service.network_info());
        });
        let weak_ui = Rc::downgrade(ui);
        glib::timeout_add_local(Duration::from_millis(100), move || {
            let Some(ui) = weak_ui.upgrade() else {
                return glib::ControlFlow::Break;
            };
            if ui.detect_count.get() != request {
                return glib::ControlFlow::Break;
            }
            let result = match rx.try_recv() {
                Ok(v) => v,
                Err(mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                Err(_) => Err(anyhow::anyhow!("检测任务已结束")),
            };
            ui.detecting.take();
            let dashboard = ui.dashboard.borrow().clone();
            if ui.detect_key() != key {
                if let Some(view) = dashboard
                    && !view.network.is_sensitive()
                {
                    view.network.set_sensitive(true);
                    view.exit_ip.set_text("点击重新检测");
                    view.network
                        .update_property(&[gtk::accessible::Property::Label("重新检测出口 IP")]);
                }
                return glib::ControlFlow::Break;
            }
            if let Some(view) = &dashboard {
                view.network.set_sensitive(true);
            }
            match result {
                Ok(info) => {
                    if let Some(view) = dashboard {
                        view.show_info(&info);
                    }
                    ui.last_detected.replace(Some((key.clone(), info)));
                }
                Err(e) => {
                    ui.last_detected.take();
                    if let Some(view) = dashboard {
                        view.exit_ip.set_text("检测失败");
                        view.network.set_tooltip_text(Some(&format!("{e:#}")));
                        view.network
                            .update_property(&[gtk::accessible::Property::Label(
                                "出口 IP 检测失败，点击重试",
                            )]);
                    }
                }
            }
            glib::ControlFlow::Break
        });
    }
    fn update(&self, at: Instant, counters: Counters) {
        let rates = self.rates.borrow_mut().record(at, counters);
        set_speed(
            &self.download,
            &self.download_unit,
            rates.map(|r| r.download as u64),
        );
        set_speed(
            &self.upload,
            &self.upload_unit,
            rates.map(|r| r.upload as u64),
        );
        self.download_total
            .set_text(&format!("累计 {}", bytes(counters.download)));
        self.upload_total
            .set_text(&format!("累计 {}", bytes(counters.upload)));
        self.connections.set_text(&counters.connections.to_string());
        self.connections.set_tooltip_text(None);
    }
    fn unavailable(&self, error: &str) {
        self.rates.borrow_mut().clear();
        set_speed(&self.download, &self.download_unit, None);
        set_speed(&self.upload, &self.upload_unit, None);
        self.connections.set_text("—");
        self.download_total.set_text("累计 —");
        self.upload_total.set_text("累计 —");
        self.connections
            .set_tooltip_text((!error.is_empty()).then_some(error));
    }
}
fn flow(min: u32, max: u32) -> gtk::FlowBox {
    let flow = gtk::FlowBox::new();
    flow.set_selection_mode(gtk::SelectionMode::None);
    flow.set_homogeneous(true);
    flow.set_min_children_per_line(min);
    flow.set_max_children_per_line(max);
    flow.set_column_spacing(14);
    flow.set_row_spacing(14);
    flow.add_css_class("dashboard-grid");
    flow
}
fn speed_card(
    icon: &str,
    title: &str,
    accent: &str,
) -> (gtk::Box, gtk::Label, gtk::Label, gtk::Label) {
    let card = card(gtk::Orientation::Vertical, 6);
    card.add_css_class("speed-card");
    card.set_widget_name(accent);
    let heading = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    heading.add_css_class(accent);
    heading.append(&gtk::Image::from_icon_name(icon));
    heading.append(&label(title, "section-title"));
    card.append(&heading);
    let value = label("—", "speed-value");
    let reading = gtk::Box::new(gtk::Orientation::Horizontal, 5);
    // Centre the reading without letting it absorb spare height: expanding
    // here made these two cards taller than the card beside them.
    reading.set_valign(gtk::Align::Center);
    reading.append(&value);
    let unit = label("B/s", "muted small");
    unit.set_valign(gtk::Align::End);
    unit.set_margin_bottom(5);
    reading.append(&unit);
    card.append(&reading);
    let total = label("累计 —", "muted small");
    total.set_valign(gtk::Align::End);
    total.set_ellipsize(gtk::pango::EllipsizeMode::End);
    card.append(&total);
    (card, value, unit, total)
}
fn set_speed(value: &gtk::Label, unit: &gtk::Label, count: Option<u64>) {
    if let Some(count) = count {
        let formatted = bytes(count);
        let (number, suffix) = formatted.split_once(' ').unwrap_or((&formatted, "B"));
        value.set_text(number);
        unit.set_text(&format!("{suffix}/s"));
    } else {
        value.set_text("—");
        unit.set_text("B/s");
    }
}
fn stat(icon: &str, title: &str, value: &str) -> (gtk::Box, gtk::Label) {
    let box_ = card(gtk::Orientation::Vertical, 16);
    box_.add_css_class("home-stat");
    let heading = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    heading.append(&gtk::Image::from_icon_name(icon));
    heading.append(&label(title, "section-title"));
    box_.append(&heading);
    let value = label(value, "home-stat-value");
    box_.append(&value);
    (box_, value)
}
