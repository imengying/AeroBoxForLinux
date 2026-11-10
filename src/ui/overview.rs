use super::*;
use aerobox_for_linux::traffic::{Counters, RateMeter};
use std::time::Instant;

pub(super) struct Dashboard {
    download: gtk::Label,
    upload: gtk::Label,
    download_total: gtk::Label,
    upload_total: gtk::Label,
    connections: gtk::Label,
    uptime: gtk::Label,
    app_memory: gtk::Label,
    core_memory: gtk::Label,
    ipv4: gtk::Label,
    ipv6: gtk::Label,
    network_status: gtk::Label,
    refresh: gtk::Button,
    rates: RefCell<RateMeter>,
    pending: Cell<bool>,
    network_pending: Cell<bool>,
}

impl Ui {
    pub(super) fn overview(self: &Rc<Self>, heading: &gtk::Box) {
        let state = self.service.snapshot();
        let status = self.service.status();
        let toggle = primary(
            if status.running { "停止" } else { "连接" },
            if status.running {
                "media-playback-stop-symbolic"
            } else {
                "media-playback-start-symbolic"
            },
        );
        if status.running {
            toggle.remove_css_class("suggested-action");
            toggle.add_css_class("destructive-action");
        }
        toggle.set_sensitive(
            status.running
                || state
                    .profiles
                    .iter()
                    .any(|p| p.id == state.settings.active_profile),
        );
        let weak = Rc::downgrade(self);
        toggle.connect_clicked(move |button| {
            if let Some(ui) = weak.upgrade() {
                if ui.jobs.get() > 0 && !status.running {
                    return;
                }
                button.set_sensitive(false);
                ui.task(
                    "切换连接",
                    move |s| Ok(if status.running { s.stop() } else { s.start() }),
                    |ui, result| {
                        ui.refresh(Page::Overview);
                        if let Err(e) = result {
                            ui.error("连接失败", format!("{e:#}"));
                        }
                    },
                );
            }
        });
        heading.append(&pill(
            if status.running {
                "已连接"
            } else {
                "未连接"
            },
            if status.running { "active" } else { "" },
        ));
        heading.append(&toggle);

        let controls = card(gtk::Orientation::Vertical, 0);
        let mode_row = detail_row("network-transmit-receive-symbolic", "出站模式", "");
        let modes = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        modes.add_css_class("linked");
        let mut first: Option<gtk::ToggleButton> = None;
        for (title, value) in [("规则", "rule"), ("全局", "global"), ("直连", "direct")] {
            let button = gtk::ToggleButton::with_label(title);
            if let Some(first) = &first {
                button.set_group(Some(first));
            } else {
                first = Some(button.clone());
            }
            button.set_active(state.settings.routing_mode == value);
            let weak = Rc::downgrade(self);
            let group = controls.downgrade();
            button.connect_toggled(move |button| {
                if !button.is_active() {
                    return;
                }
                if let Some(ui) = weak.upgrade() {
                    if let Some(group) = group.upgrade() {
                        group.set_sensitive(false);
                    }
                    ui.task(
                        "切换出站模式",
                        move |s| Ok(s.set_routing_mode(value)),
                        |ui, result| {
                            ui.refresh(Page::Overview);
                            if let Err(e) = result {
                                ui.error("切换失败", format!("{e:#}"));
                            }
                        },
                    );
                }
            });
            modes.append(&button);
        }
        mode_row.append(&modes);
        controls.append(&mode_row);
        let switches = gtk::Box::new(gtk::Orientation::Horizontal, 20);
        switches.add_css_class("quick-switches");
        switches.set_homogeneous(true);
        for (title, kind, active) in [
            ("系统代理", 0, status.proxy),
            ("虚拟网卡", 1, state.settings.tun_enabled),
            ("IPv6", 2, state.settings.ipv6),
        ] {
            let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
            let name = label(title, "");
            name.set_hexpand(true);
            row.append(&name);
            let switch = gtk::Switch::new();
            switch.set_valign(gtk::Align::Center);
            switch.set_active(active);
            switch.update_property(&[gtk::accessible::Property::Label(title)]);
            if kind == 0 {
                switch.set_sensitive(status.running || status.proxy);
            }
            let weak = Rc::downgrade(self);
            let group = controls.downgrade();
            switch.connect_state_set(move |switch, enabled| {
                if let Some(ui) = weak.upgrade() {
                    switch.set_sensitive(false);
                    if let Some(group) = group.upgrade() {
                        group.set_sensitive(false);
                    }
                    ui.task(
                        title,
                        move |s| {
                            Ok(if kind == 0 {
                                s.set_proxy(enabled)
                            } else {
                                let mut settings = s.snapshot().settings;
                                if kind == 1 {
                                    settings.tun_enabled = enabled;
                                } else {
                                    settings.ipv6 = enabled;
                                }
                                s.apply_settings(settings)
                            })
                        },
                        |ui, result| {
                            ui.refresh(Page::Overview);
                            if let Err(e) = result {
                                ui.error("设置失败", format!("{e:#}"));
                            }
                        },
                    );
                }
                glib::Propagation::Stop
            });
            row.append(&switch);
            switches.append(&row);
        }
        controls.append(&switches);
        self.body.append(&controls);

        let metrics = gtk::FlowBox::new();
        metrics.add_css_class("metrics");
        metrics.set_selection_mode(gtk::SelectionMode::None);
        metrics.set_homogeneous(true);
        metrics.set_min_children_per_line(2);
        metrics.set_max_children_per_line(3);
        metrics.set_column_spacing(14);
        metrics.set_row_spacing(14);
        let (down, download, download_total) = metric("go-down-symbolic", "下载", "—", "累计 —");
        let (up, upload, upload_total) = metric("go-up-symbolic", "上传", "—", "累计 —");
        let (connections_card, connections, _) =
            metric("network-workgroup-symbolic", "活跃连接", "—", "");
        let (uptime_card, uptime, _) = metric(
            "preferences-system-time-symbolic",
            "运行时间",
            &duration(status.uptime),
            "",
        );
        let (core_card, core_memory, _) = metric("drive-harddisk-symbolic", "内核内存", "—", "");
        let (app_card, app_memory, _) =
            metric("application-x-executable-symbolic", "应用内存", "—", "");
        for item in [
            &down,
            &up,
            &connections_card,
            &uptime_card,
            &core_card,
            &app_card,
        ] {
            metrics.insert(item, -1);
        }
        self.body.append(&metrics);

        let network = card(gtk::Orientation::Vertical, 14);
        network.add_css_class("padded-card");
        let header = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        let title = label("网络检测", "section-title");
        title.set_hexpand(true);
        header.append(&title);
        let network_status = label("", "muted small");
        header.append(&network_status);
        let refresh = icon_button("view-refresh-symbolic", "检测当前出口 IP");
        header.append(&refresh);
        network.append(&header);
        let ipv4 = ip_row(&network, "IPv4");
        let ipv6 = ip_row(&network, "IPv6");
        if !state.settings.ipv6 {
            ipv6.set_text("已关闭");
        }
        self.body.append(&network);
        let dashboard = Rc::new(Dashboard {
            download,
            upload,
            download_total,
            upload_total,
            connections,
            uptime,
            app_memory,
            core_memory,
            ipv4,
            ipv6,
            network_status,
            refresh: refresh.clone(),
            rates: RefCell::new(RateMeter::default()),
            pending: Cell::new(false),
            network_pending: Cell::new(false),
        });
        let weak = Rc::downgrade(self);
        let weak_dashboard = Rc::downgrade(&dashboard);
        refresh.connect_clicked(move |_| {
            if let (Some(ui), Some(dashboard)) = (weak.upgrade(), weak_dashboard.upgrade()) {
                dashboard.detect(&ui);
            }
        });
        dashboard.tick(self);
        if state.settings.auto_detect_ip {
            dashboard.detect(self);
        }
        self.dashboard.replace(Some(dashboard));
    }
}

impl Dashboard {
    pub(super) fn tick(self: &Rc<Self>, ui: &Rc<Ui>) {
        let status = ui.service.status();
        self.uptime.set_text(&duration(status.uptime));
        let memory = ui.service.memory_usage();
        self.app_memory
            .set_text(&memory.app_bytes.map(bytes).unwrap_or_else(|| "—".into()));
        self.core_memory
            .set_text(&memory.core_bytes.map(bytes).unwrap_or_else(|| "—".into()));
        if !status.running || self.pending.replace(true) {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let service = ui.service.clone();
        std::thread::spawn(move || {
            let result = service.traffic();
            let _ = tx.send((Instant::now(), result));
        });
        let weak = Rc::downgrade(self);
        let weak_ui = Rc::downgrade(ui);
        glib::timeout_add_local(Duration::from_millis(50), move || {
            let (Some(dashboard), Some(ui)) = (weak.upgrade(), weak_ui.upgrade()) else {
                return glib::ControlFlow::Break;
            };
            match rx.try_recv() {
                Ok((at, result)) => {
                    dashboard.pending.set(false);
                    if ui.service.status().pid == status.pid {
                        match result {
                            Ok(counters) => dashboard.update(at, counters),
                            Err(e) => dashboard.unavailable(&format!("{e:#}")),
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
    fn detect(self: &Rc<Self>, ui: &Rc<Ui>) {
        if self.network_pending.replace(true) {
            return;
        }
        self.refresh.set_sensitive(false);
        self.network_status.set_text("检测中…");
        self.ipv4.set_text("—");
        self.ipv6.set_text(if ui.service.snapshot().settings.ipv6 {
            "—"
        } else {
            "已关闭"
        });
        let status = ui.service.status();
        let service = ui.service.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(service.network_info());
        });
        let weak = Rc::downgrade(self);
        let weak_ui = Rc::downgrade(ui);
        glib::timeout_add_local(Duration::from_millis(100), move || {
            let (Some(dashboard), Some(ui)) = (weak.upgrade(), weak_ui.upgrade()) else {
                return glib::ControlFlow::Break;
            };
            let result = match rx.try_recv() {
                Ok(v) => v,
                Err(mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                Err(_) => Err(anyhow::anyhow!("检测任务已结束")),
            };
            dashboard.network_pending.set(false);
            dashboard.refresh.set_sensitive(true);
            if ui.service.status().pid != status.pid {
                dashboard.network_status.set_text("请重新检测");
                return glib::ControlFlow::Break;
            }
            match result {
                Ok(info) => {
                    dashboard
                        .ipv4
                        .set_text(info.ipv4.as_deref().unwrap_or("不可用"));
                    if ui.service.snapshot().settings.ipv6 {
                        dashboard
                            .ipv6
                            .set_text(info.ipv6.as_deref().unwrap_or("不可用"));
                    }
                    dashboard.network_status.set_text(if info.via_proxy {
                        "当前出口"
                    } else {
                        "直连出口"
                    });
                    dashboard.network_status.set_tooltip_text(None);
                }
                Err(e) => {
                    dashboard.network_status.set_text("检测失败");
                    dashboard
                        .network_status
                        .set_tooltip_text(Some(&format!("{e:#}")));
                }
            }
            glib::ControlFlow::Break
        });
    }
    fn update(&self, at: Instant, counters: Counters) {
        let rates = self.rates.borrow_mut().record(at, counters);
        self.download.set_text(
            &rates.map_or_else(|| "—".into(), |r| format!("{}/s", bytes(r.download as u64))),
        );
        self.upload.set_text(
            &rates.map_or_else(|| "—".into(), |r| format!("{}/s", bytes(r.upload as u64))),
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
        self.download.set_text("—");
        self.upload.set_text("—");
        self.connections.set_text("—");
        self.download_total.set_text("累计 —");
        self.upload_total.set_text("累计 —");
        self.connections.set_tooltip_text(Some(error));
    }
}
fn metric(
    icon: &str,
    title: &str,
    value: &str,
    caption: &str,
) -> (gtk::Box, gtk::Label, gtk::Label) {
    let card = card(gtk::Orientation::Vertical, 10);
    card.add_css_class("stat-card");
    let heading = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    heading.append(&gtk::Image::from_icon_name(icon));
    heading.append(&label(title, "muted"));
    card.append(&heading);
    let value = label(value, "metric-value");
    card.append(&value);
    let caption = label(caption, "resource-subtitle");
    if !caption.text().is_empty() {
        card.append(&caption);
    }
    (card, value, caption)
}
fn ip_row(parent: &gtk::Box, title: &str) -> gtk::Label {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 16);
    row.append(&label(title, "muted"));
    let value = label("—", "ip-address");
    value.set_selectable(true);
    value.set_hexpand(true);
    value.set_wrap(true);
    value.set_wrap_mode(gtk::pango::WrapMode::Char);
    row.append(&value);
    parent.append(&row);
    value
}
