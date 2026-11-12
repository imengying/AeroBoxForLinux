use super::*;
use aerobox_for_linux::traffic::{Counters, RateMeter};
use std::time::Instant;

pub(super) struct Dashboard {
    controls: gtk::Box,
    modes: Vec<(&'static str, gtk::ToggleButton)>,
    download: gtk::Label,
    upload: gtk::Label,
    download_unit: gtk::Label,
    upload_unit: gtk::Label,
    download_total: gtk::Label,
    upload_total: gtk::Label,
    connections: gtk::Label,
    uptime: gtk::Label,
    memory: gtk::Label,
    ipv4: gtk::Label,
    ipv6: gtk::Label,
    network_status: gtk::Label,
    refresh: gtk::Button,
    rates: RefCell<RateMeter>,
    pending: Cell<bool>,
    memory_at: Cell<Option<Instant>>,
    network_pending: Cell<bool>,
}

impl Ui {
    pub(super) fn home(self: &Rc<Self>) {
        self.body.add_css_class("home-page");
        self.body.set_spacing(16);
        self.body.set_margin_bottom(32);
        self.scroll.set_margin_bottom(100);
        let state = self.service.snapshot();
        let status = self.service.status();

        let toggle = primary(
            if status.running { "停止" } else { "启动" },
            if status.running {
                "media-playback-stop-symbolic"
            } else {
                "media-playback-start-symbolic"
            },
        );
        toggle.add_css_class("home-start");
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
        });
        self.floating.add_overlay(&toggle);
        self.home_action.replace(Some(toggle));

        let top = flow(1, 2);
        follow_width(&top, 232, 14, 2);
        top.set_vexpand(false);
        top.add_css_class("home-top");
        let network = card(gtk::Orientation::Vertical, 12);
        network.add_css_class("home-network");
        let header = gtk::Box::new(gtk::Orientation::Horizontal, 10);
        header.append(&gtk::Image::from_icon_name("network-wireless-symbolic"));
        let title = label("出口 IP", "section-title");
        title.set_hexpand(true);
        header.append(&title);
        let network_status = label("", "muted small");
        header.append(&network_status);
        let refresh = icon_button("view-refresh-symbolic", "检测当前出口 IP");
        header.append(&refresh);
        network.append(&header);
        let ipv4 = ip_row(&network, "IPv4", true);
        ipv4.add_css_class("exit-ip");
        let ipv6 = ip_row(&network, "IPv6", false);
        if !state.settings.ipv6 {
            ipv6.set_text("已关闭");
        }
        top.insert(&network, -1);

        let speeds = gtk::Box::new(gtk::Orientation::Horizontal, 14);
        speeds.set_homogeneous(true);
        let (down, download, download_unit, download_total) =
            speed_card("go-down-symbolic", "下载", "download");
        let (up, upload, upload_unit, upload_total) =
            speed_card("go-up-symbolic", "上传", "upload");
        speeds.append(&down);
        speeds.append(&up);
        top.insert(&speeds, -1);
        self.body.append(&top);

        let controls = gtk::Box::new(gtk::Orientation::Vertical, 0);
        controls.set_sensitive(self.jobs.get() == 0);
        let control_grid = flow(1, 2);
        follow_width(&control_grid, 232, 14, 2);
        let mode_row = card(gtk::Orientation::Vertical, 12);
        mode_row.add_css_class("home-mode");
        let title = label("出站模式", "section-title");
        mode_row.append(&title);
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
            let group = controls.downgrade();
            button.connect_clicked(move |button| {
                if !button.is_active() {
                    return;
                }
                if let Some(ui) = weak.upgrade() {
                    if let Some(group) = group.upgrade() {
                        group.set_sensitive(false);
                    }
                    ui.button_task(
                        button.upcast_ref::<gtk::Button>(),
                        "切换中…",
                        move |s| s.set_routing_mode(value),
                        |ui, result| {
                            ui.refresh(Page::Home);
                            if let Err(e) = result {
                                ui.error("切换失败", format!("{e:#}"));
                            }
                        },
                    );
                }
            });
            modes.append(&button);
            mode_buttons.push((value, button));
        }
        mode_row.append(&modes);
        control_grid.insert(&mode_row, -1);

        let switches = card(gtk::Orientation::Vertical, 0);
        switches.add_css_class("home-takeover");
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
            switch.update_property(&[gtk::accessible::Property::Label(title)]);
            let weak = Rc::downgrade(self);
            let group = controls.downgrade();
            switch.connect_state_set(move |_, enabled| {
                if let Some(ui) = weak.upgrade() {
                    if let Some(group) = group.upgrade() {
                        group.set_sensitive(false);
                    }
                    ui.task(
                        title,
                        move |s| {
                            Ok(if system {
                                s.set_system_proxy_enabled(enabled)
                            } else {
                                let mut settings = s.snapshot().settings;
                                settings.tun_enabled = enabled;
                                s.apply_settings(settings)
                            })
                        },
                        |ui, result| {
                            ui.refresh(Page::Home);
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
        control_grid.insert(&switches, -1);
        controls.append(&control_grid);
        self.body.append(&controls);

        let stats = flow(1, 3);
        // Three equal cards only while they stay readable; narrow windows drop
        // to two or one instead of squeezing the labels.
        follow_width(&stats, 168, 14, 3);
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
            download,
            upload,
            download_unit,
            upload_unit,
            download_total,
            upload_total,
            connections,
            uptime,
            memory,
            ipv4,
            ipv6,
            network_status,
            refresh: refresh.clone(),
            rates: RefCell::new(RateMeter::default()),
            pending: Cell::new(false),
            memory_at: Cell::new(None),
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
        self.controls.set_sensitive(ui.jobs.get() == 0);
        let status = ui.service.status();
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
                    if ui.service.status().pid == status.pid {
                        if ui.jobs.get() == 0
                            && let Ok(mode) = mode
                        {
                            for (value, button) in &dashboard.modes {
                                if *value == mode {
                                    button.set_active(true);
                                }
                            }
                        }
                        if let Some(memory) = memory {
                            dashboard.memory.set_text(
                                &memory.total_bytes.map(bytes).unwrap_or_else(|| "—".into()),
                            );
                            dashboard.memory.set_tooltip_text(Some(&format!(
                                "AeroBox 与内核合计（{}）",
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
        self.connections.set_tooltip_text(Some(error));
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
    let card = card(gtk::Orientation::Vertical, 14);
    card.add_css_class("speed-card");
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
fn ip_row(parent: &gtk::Box, title: &str, prominent: bool) -> gtk::Label {
    let row = gtk::Box::new(
        if prominent {
            gtk::Orientation::Vertical
        } else {
            gtk::Orientation::Horizontal
        },
        6,
    );
    row.append(&label(title, "muted small"));
    let value = label("—", "ip-address");
    value.set_selectable(true);
    value.set_hexpand(true);
    value.set_wrap(true);
    value.set_wrap_mode(gtk::pango::WrapMode::Char);
    value.set_max_width_chars(30);
    row.append(&value);
    parent.append(&row);
    value
}
