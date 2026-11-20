use super::*;

pub(super) struct CorePanel {
    version: adw::ActionRow,
    status: adw::ActionRow,
    toggle: gtk::Button,
    restart: gtk::Button,
    check: gtk::Button,
    pending: Cell<bool>,
    key: Cell<Option<Option<u64>>>,
}

impl Ui {
    pub(super) fn core_panel(self: &Rc<Self>, page: &gtk::Box) {
        let group = adw::PreferencesGroup::builder().title("运行状态").build();
        let version = adw::ActionRow::builder()
            .title("AeroBox 内置引擎")
            .subtitle("读取中…")
            .build();
        version.set_widget_name("embedded-engine-version");
        group.add(&version);
        let status = adw::ActionRow::builder().title("状态").build();
        let toggle = gtk::Button::with_label("启动");
        toggle.set_valign(gtk::Align::Center);
        status.add_suffix(&toggle);
        group.add(&status);
        page.append(&group);
        let actions = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        let check = gtk::Button::with_label("检查配置");
        let restart = gtk::Button::with_label("重启内核");
        let logs = gtk::Button::with_label("查看日志");
        for button in [&check, &restart, &logs] {
            actions.append(button);
        }
        page.append(&actions);
        let diagnose = gtk::Button::with_label("连接诊断");
        diagnose.set_halign(gtk::Align::Start);
        diagnose.set_widget_name("connection-diagnostics");
        page.append(&diagnose);
        let weak = Rc::downgrade(self);
        diagnose.connect_clicked(move |button| {
            if let Some(ui) = weak.upgrade() {
                ui.button_task(
                    button,
                    "检测中…",
                    |s| s.diagnose_connection(),
                    |ui, result| {
                        let report = match result {
                            Ok(report) => report,
                            Err(error) => format!("{error:#}"),
                        };
                        let executable = std::env::current_exe()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default();
                        let text = format!(
                            "AeroBox {}\n程序：{}\n\n{}",
                            option_env!("AEROBOX_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")),
                            executable,
                            report
                        );
                        let dialog = alert_dialog("连接诊断", &text);
                        dialog.add_response("copy", "复制结果");
                        dialog.add_response("close", "关闭");
                        dialog.set_default_response(Some("close"));
                        dialog.set_close_response("close");
                        let clipboard = ui.window.clipboard();
                        dialog.connect_response(Some("copy"), move |_, _| {
                            clipboard.set_text(&text);
                        });
                        dialog.present(Some(&ui.window));
                    },
                );
            }
        });
        let panel = Rc::new(CorePanel {
            version,
            status,
            toggle: toggle.clone(),
            restart: restart.clone(),
            check: check.clone(),
            pending: Cell::new(false),
            key: Cell::new(None),
        });
        self.core.replace(Some(panel.clone()));
        panel.tick(self);

        let weak = Rc::downgrade(self);
        toggle.connect_clicked(move |button| {
            if let Some(ui) = weak.upgrade() {
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
                        if let Err(e) = result {
                            ui.error("内核操作失败", format!("{e:#}"));
                        }
                        if let Some(panel) = ui.core.borrow().as_ref() {
                            panel.tick(ui);
                        }
                    },
                );
            }
        });
        let weak = Rc::downgrade(self);
        restart.connect_clicked(move |button| {
            if let Some(ui) = weak.upgrade()
                && ui.jobs.get() == 0
            {
                ui.button_task(
                    button,
                    "重启中…",
                    |s| s.restart(),
                    |ui, result| {
                        match result {
                            Ok(()) => ui.notify("内核已重启"),
                            Err(e) => ui.error("重启失败", format!("{e:#}")),
                        }
                        if let Some(panel) = ui.core.borrow().as_ref() {
                            panel.tick(ui);
                        }
                    },
                );
            }
        });
        let weak = Rc::downgrade(self);
        check.connect_clicked(move |button| {
            if let Some(ui) = weak.upgrade()
                && ui.jobs.get() == 0
            {
                ui.button_task(
                    button,
                    "检查中…",
                    |s| s.check_current(),
                    |ui, result| match result {
                        Ok(()) => ui.notify("配置检查通过"),
                        Err(e) => ui.error("配置检查失败", format!("{e:#}")),
                    },
                );
            }
        });
        let weak = Rc::downgrade(self);
        logs.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.navigate(Page::Logs);
            }
        });
    }
}

impl CorePanel {
    pub(super) fn tick(self: &Rc<Self>, ui: &Rc<Ui>) {
        let status = ui.service.status();
        let idle = ui.jobs.get() == 0;
        self.toggle.set_sensitive(idle || status.running);
        self.restart.set_sensitive(idle && status.running);
        self.check.set_sensitive(idle);
        if idle {
            self.toggle
                .set_label(if status.running { "停止" } else { "启动" });
        }
        self.status.set_subtitle(&if status.running {
            format!("运行中 · {}", duration(status.uptime))
        } else {
            "已停止".into()
        });
        let generation = status.generation;
        if !idle || self.key.get() == Some(generation) || self.pending.replace(true) {
            return;
        }
        self.key.set(Some(generation));
        self.version.set_subtitle("读取中…");
        let service = ui.service.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(service.core_info());
        });
        let weak = Rc::downgrade(self);
        let weak_ui = Rc::downgrade(ui);
        glib::timeout_add_local(Duration::from_millis(100), move || {
            let (Some(panel), Some(ui)) = (weak.upgrade(), weak_ui.upgrade()) else {
                return glib::ControlFlow::Break;
            };
            let result = match rx.try_recv() {
                Ok(result) => result,
                Err(mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                Err(_) => Err(anyhow::anyhow!("读取任务已结束")),
            };
            panel.pending.set(false);
            if ui.service.status().generation != generation {
                panel.key.set(None);
                panel.tick(&ui);
                return glib::ControlFlow::Break;
            }
            match result {
                Ok(info) => {
                    panel.version.set_title(&info.name);
                    panel.version.set_subtitle(&info.version);
                    panel.version.set_tooltip_text(None);
                }
                Err(error) => {
                    panel.version.set_subtitle("无法读取引擎状态");
                    panel.version.set_tooltip_text(Some(&format!("{error:#}")));
                }
            }
            glib::ControlFlow::Break
        });
    }
}

pub(super) async fn smoke_info(ui: &Rc<Ui>) -> Result<()> {
    let panel = ui.core.borrow().clone().context("缺少内置引擎状态")?;
    let start = std::time::Instant::now();
    while panel.pending.get() {
        anyhow::ensure!(
            start.elapsed() < Duration::from_secs(5),
            "内置引擎状态读取超时"
        );
        glib::timeout_future(Duration::from_millis(16)).await;
    }
    let info = ui.service.core_info()?;
    anyhow::ensure!(
        !info.name.is_empty()
            && !info.version.is_empty()
            && panel.version.title() == info.name
            && panel.version.subtitle().as_deref() == Some(info.version.as_str()),
        "内置引擎信息未显示"
    );
    anyhow::ensure!(
        !descendants(&ui.body).iter().any(|widget| {
            widget
                .downcast_ref::<gtk::Button>()
                .is_some_and(|button| button.label().as_deref() == Some("下载 / 更新"))
                || widget.downcast_ref::<gtk::Entry>().is_some_and(|entry| {
                    entry.placeholder_text().as_deref() == Some("内核路径（留空自动检测）")
                })
        }),
        "设置仍需要外部内核"
    );
    Ok(())
}
