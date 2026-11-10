use super::*;
use aerobox_for_linux::traffic::{Counters, HISTORY_SECONDS, History};
use std::time::Instant;

pub(super) struct Dashboard {
    download: gtk::Label,
    upload: gtk::Label,
    download_total: gtk::Label,
    upload_total: gtk::Label,
    connections: gtk::Label,
    uptime: gtk::Label,
    notice: gtk::Label,
    scale: gtk::Label,
    chart: gtk::DrawingArea,
    history: Rc<RefCell<History>>,
    pending: Cell<bool>,
}

impl Ui {
    pub(super) fn overview(self: &Rc<Self>, _heading: &gtk::Box) {
        let state = self.service.snapshot();
        let status = self.service.status();
        let active = state
            .profiles
            .iter()
            .find(|p| p.id == state.settings.active_profile);

        let hero = card(gtk::Orientation::Horizontal, 20);
        hero.add_css_class("hero-card");
        hero.add_css_class("connection-card");
        let power = gtk::Image::from_icon_name(if status.running {
            "network-transmit-receive-symbolic"
        } else {
            "system-shutdown-symbolic"
        });
        power.set_pixel_size(28);
        power.add_css_class("hero-icon");
        power.set_valign(gtk::Align::Center);
        hero.append(&power);
        let text = gtk::Box::new(gtk::Orientation::Vertical, 8);
        text.set_hexpand(true);
        text.set_valign(gtk::Align::Center);
        let title = label(
            if status.running {
                "代理服务运行中"
            } else {
                "准备好，即可连接"
            },
            "hero-title",
        );
        title.set_wrap(true);
        text.append(&title);
        let subtitle = label(
            if status.running {
                "查看网络活动，随时掌握连接状态。"
            } else if active.is_none() {
                "在配置页添加并选择配置后，即可启动。"
            } else {
                "启动代理服务，查看实时流量与连接。"
            },
            "page-subtitle",
        );
        subtitle.set_wrap(true);
        text.append(&subtitle);
        hero.append(&text);
        let toggle = primary(
            if status.running {
                "停止连接"
            } else {
                "启动连接"
            },
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
        toggle.set_sensitive(status.running || active.is_some());
        let weak = Rc::downgrade(self);
        toggle.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                if ui.jobs.get() > 0 && !status.running {
                    return;
                }
                ui.task(
                    "切换连接",
                    move |s| if status.running { s.stop() } else { s.start() },
                    |ui, ()| ui.refresh(Page::Overview),
                );
            }
        });
        hero.append(&toggle);
        self.body.append(&hero);

        let metrics = gtk::FlowBox::new();
        metrics.add_css_class("metrics");
        metrics.set_selection_mode(gtk::SelectionMode::None);
        metrics.set_homogeneous(true);
        metrics.set_min_children_per_line(1);
        metrics.set_max_children_per_line(2);
        metrics.set_column_spacing(14);
        metrics.set_row_spacing(14);
        let (download_card, download, download_total) = metric(
            "go-down-symbolic",
            "下载速度",
            "—",
            "本次下载 —",
            "download",
        );
        let (upload_card, upload, upload_total) =
            metric("go-up-symbolic", "上传速度", "—", "本次上传 —", "upload");
        let (connections_card, connections, _) = metric(
            "network-workgroup-symbolic",
            "活跃连接",
            "—",
            "正在经过内核的连接",
            "",
        );
        let (uptime_card, uptime, _) = metric(
            "preferences-system-time-symbolic",
            "运行时间",
            &duration(status.uptime),
            "本次持续运行",
            "",
        );
        for pair in [
            [&download_card, &upload_card],
            [&connections_card, &uptime_card],
        ] {
            let row = gtk::Box::new(gtk::Orientation::Horizontal, 14);
            row.set_homogeneous(true);
            for item in pair {
                row.append(item);
            }
            metrics.insert(&row, -1);
        }
        self.body.append(&metrics);

        let traffic = card(gtk::Orientation::Vertical, 12);
        traffic.add_css_class("padded-card");
        let chart_heading = gtk::Box::new(gtk::Orientation::Horizontal, 14);
        let title = label("流量趋势", "section-title");
        title.set_hexpand(true);
        chart_heading.append(&title);
        chart_heading.append(&label("↓ 下载", "download small"));
        chart_heading.append(&label("↑ 上传", "upload small"));
        chart_heading.append(&label("最近 60 秒", "muted small"));
        traffic.append(&chart_heading);
        let plot = gtk::Overlay::new();
        let chart = gtk::DrawingArea::new();
        chart.set_content_height(144);
        chart.set_hexpand(true);
        chart.update_property(&[gtk::accessible::Property::Label(
            "最近 60 秒上传和下载速度趋势；当前数值显示在上方",
        )]);
        let history = Rc::new(RefCell::new(History::default()));
        let chart_history = history.clone();
        chart.set_draw_func(move |_, ctx, width, height| {
            draw_chart(ctx, width as f64, height as f64, &chart_history.borrow());
        });
        plot.set_child(Some(&chart));
        let notice = label(
            if status.running {
                "正在读取流量统计…"
            } else {
                "启动连接后显示实时流量"
            },
            "chart-notice",
        );
        notice.set_halign(gtk::Align::Center);
        notice.set_valign(gtk::Align::Center);
        notice.set_wrap(true);
        notice.set_justify(gtk::Justification::Center);
        plot.add_overlay(&notice);
        traffic.append(&plot);
        let chart_footer = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        chart_footer.append(&label("60 秒前", "muted small"));
        let scale = label("", "muted small");
        scale.set_hexpand(true);
        scale.set_halign(gtk::Align::Center);
        chart_footer.append(&scale);
        chart_footer.append(&label("现在", "muted small"));
        traffic.append(&chart_footer);
        self.body.append(&traffic);

        let controls = card(gtk::Orientation::Vertical, 0);
        let proxy = detail_row(
            "network-wired-symbolic",
            "系统代理",
            "让支持系统代理的桌面应用通过本地代理连接",
        );
        let proxy_switch = gtk::Switch::new();
        proxy_switch.set_valign(gtk::Align::Center);
        proxy_switch.set_active(status.proxy);
        proxy_switch.set_sensitive(status.running || status.proxy);
        proxy_switch.update_property(&[gtk::accessible::Property::Label("系统代理")]);
        let weak = Rc::downgrade(self);
        proxy_switch.connect_state_set(move |switch, enabled| {
            if let Some(ui) = weak.upgrade() {
                switch.set_sensitive(false);
                ui.task(
                    "设置系统代理",
                    move |s| Ok(s.set_proxy(enabled)),
                    |ui, result| {
                        ui.refresh(Page::Overview);
                        if let Err(e) = result {
                            ui.error("设置系统代理失败", e);
                        }
                    },
                );
            }
            glib::Propagation::Stop
        });
        proxy.append(&proxy_switch);
        controls.append(&proxy);
        self.body.append(&controls);

        // Keep secondary details unobtrusive and leave configuration editing on
        // the Profiles page. These are configured endpoints, not reachability claims.
        if let Some(profile) = active {
            let inbounds = profile.config["inbounds"].as_array();
            let mixed = inbounds.and_then(|v| {
                v.iter()
                    .find(|i| matches!(i["type"].as_str(), Some("mixed" | "http" | "socks")))
            });
            let tun = inbounds.is_some_and(|v| v.iter().any(|i| i["type"] == "tun"));
            let details = gtk::Box::new(gtk::Orientation::Horizontal, 16);
            if let Some(inbound) = mixed {
                let host = inbound["listen"].as_str().unwrap_or("127.0.0.1");
                let host = if host.contains(':') {
                    format!("[{host}]")
                } else {
                    host.to_string()
                };
                if let Some(port) = inbound["listen_port"].as_u64() {
                    details.append(&label(&format!("代理入口  {host}:{port}"), "muted small"));
                }
            }
            details.append(&label(
                if tun {
                    "TUN 入站已配置"
                } else {
                    "TUN 入站未配置"
                },
                "muted small",
            ));
            self.body.append(&details);
        }

        let dashboard = Rc::new(Dashboard {
            download,
            upload,
            download_total,
            upload_total,
            connections,
            uptime,
            notice,
            scale,
            chart,
            history,
            pending: Cell::new(false),
        });
        dashboard.tick(self);
        self.dashboard.replace(Some(dashboard));
    }
}

impl Dashboard {
    pub(super) fn tick(self: &Rc<Self>, ui: &Rc<Ui>) {
        let status = ui.service.status();
        self.uptime.set_text(&duration(status.uptime));
        if !status.running || self.pending.replace(true) {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let service = ui.service.clone();
        std::thread::spawn(move || {
            let counters = service.traffic();
            let _ = tx.send((Instant::now(), counters));
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
                            Err(error) => dashboard.unavailable(&format!("{error:#}")),
                        }
                    }
                    glib::ControlFlow::Break
                }
                Err(mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                Err(mpsc::TryRecvError::Disconnected) => {
                    dashboard.pending.set(false);
                    dashboard.unavailable("流量统计任务意外结束");
                    glib::ControlFlow::Break
                }
            }
        });
    }

    fn update(&self, at: Instant, counters: Counters) {
        let sample = self.history.borrow_mut().record(at, counters);
        self.download
            .set_text(&sample.map_or_else(|| "—".into(), |s| speed(s.download)));
        self.upload
            .set_text(&sample.map_or_else(|| "—".into(), |s| speed(s.upload)));
        self.download_total
            .set_text(&format!("本次下载 {}", bytes(counters.download)));
        self.upload_total
            .set_text(&format!("本次上传 {}", bytes(counters.upload)));
        self.connections.set_text(&counters.connections.to_string());
        self.notice.set_text("正在采集流量…");
        self.notice.set_tooltip_text(None);
        self.notice.set_visible(sample.is_none());
        let peak = chart_peak(&self.history.borrow());
        self.scale.set_text(&format!("刻度上限 {}", speed(peak)));
        self.chart.queue_draw();
    }

    fn unavailable(&self, error: &str) {
        self.history.borrow_mut().clear();
        self.download.set_text("—");
        self.upload.set_text("—");
        self.connections.set_text("—");
        self.download_total.set_text("本次下载 —");
        self.upload_total.set_text("本次上传 —");
        self.scale.set_text("");
        self.notice.set_text("流量统计暂不可用，正在重试");
        self.notice.set_tooltip_text(Some(error));
        self.notice.set_visible(true);
        self.chart.queue_draw();
    }
}

fn metric(
    icon: &str,
    title: &str,
    value: &str,
    caption: &str,
    class: &str,
) -> (gtk::Box, gtk::Label, gtk::Label) {
    let card = card(gtk::Orientation::Vertical, 8);
    card.add_css_class("stat-card");
    let heading = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let image = gtk::Image::from_icon_name(icon);
    if !class.is_empty() {
        image.add_css_class(class);
    }
    heading.append(&image);
    heading.append(&label(title, "muted small"));
    card.append(&heading);
    let value = label(value, "metric-value");
    card.append(&value);
    let caption = label(caption, "resource-subtitle");
    card.append(&caption);
    (card, value, caption)
}

fn speed(value: f64) -> String {
    format!("{}/s", bytes(value.max(0.0) as u64))
}

fn chart_peak(history: &History) -> f64 {
    history
        .samples
        .iter()
        .fold(1024.0_f64, |max, s| max.max(s.download).max(s.upload))
        * 1.2
}

fn draw_chart(ctx: &gtk::cairo::Context, width: f64, height: f64, history: &History) {
    let dark = adw::StyleManager::default().is_dark();
    let grid = if dark { 0.8 } else { 0.3 };
    ctx.set_source_rgba(grid, grid, grid, 0.12);
    ctx.set_line_width(1.0);
    for step in 0..=3 {
        let y = 8.0 + (height - 16.0) * step as f64 / 3.0;
        ctx.move_to(0.0, y);
        ctx.line_to(width, y);
    }
    let _ = ctx.stroke();
    let now = Instant::now();
    let peak = chart_peak(history);
    let baseline = height - 8.0;
    for download in [true, false] {
        let points: Vec<_> = history
            .samples
            .iter()
            .filter_map(|sample| {
                let age = now.saturating_duration_since(sample.at).as_secs_f64();
                if age > HISTORY_SECONDS as f64 {
                    return None;
                }
                let x = width * (1.0 - age / HISTORY_SECONDS as f64);
                let rate = if download {
                    sample.download
                } else {
                    sample.upload
                };
                Some((x, baseline - (height - 16.0) * rate / peak))
            })
            .collect();
        let Some(&(first_x, first_y)) = points.first() else {
            continue;
        };
        let color = if download {
            if dark {
                (0.38, 0.84, 0.76)
            } else {
                (0.03, 0.50, 0.51)
            }
        } else if dark {
            (0.55, 0.68, 1.0)
        } else {
            (0.31, 0.43, 0.83)
        };
        ctx.move_to(first_x, baseline);
        for &(x, y) in &points {
            ctx.line_to(x, y);
        }
        ctx.line_to(points.last().unwrap().0, baseline);
        ctx.close_path();
        ctx.set_source_rgba(color.0, color.1, color.2, 0.08);
        let _ = ctx.fill();
        ctx.move_to(first_x, first_y);
        for &(x, y) in points.iter().skip(1) {
            ctx.line_to(x, y);
        }
        ctx.set_source_rgb(color.0, color.1, color.2);
        ctx.set_line_width(2.0);
        ctx.set_line_join(gtk::cairo::LineJoin::Round);
        let _ = ctx.stroke();
        if let Some(&(x, y)) = points.last() {
            ctx.arc(x, y, 2.5, 0.0, std::f64::consts::TAU);
            let _ = ctx.fill();
        }
    }
}
