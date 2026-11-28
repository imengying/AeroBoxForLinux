use super::*;
use sourceview::prelude::BufferExt as _;
use std::time::Instant;

pub(super) fn seed_smoke(service: &Service) -> Result<()> {
    service.update(|state| {
        state.settings.theme="light".into();state.settings.auto_detect_ip=false;
        let subscription=Subscription {name:"日常连接".into(),selected_node:Some("日本 · 01".into()),nodes:vec![
            json!({"type":"shadowsocks","tag":"香港 · 01","server":"hk.example.invalid","server_port":443,"method":"aes-128-gcm","password":"smoke-fixture"}),
            json!({"type":"trojan","tag":"日本 · 01","server":"jp.example.invalid","server_port":443,"password":"smoke-fixture","tls":{"enabled":true}}),
            json!({"type":"hysteria2","tag":"新加坡 · 01","server":"sg.example.invalid","server_port":443,"password":"smoke-fixture","tls":{"enabled":true}}),
            json!({"type":"shadowsocks","tag":"美国 · 01","server":"us.example.invalid","server_port":443,"method":"aes-128-gcm","password":"smoke-fixture"}),
            json!({"type":"trojan","tag":"德国 · 01","server":"de.example.invalid","server_port":443,"password":"smoke-fixture","tls":{"enabled":true}}),
            json!({"type":"socks","tag":"本地备用","server":"127.0.0.1","server_port":1080}),
        ],updated:model::now()-1200,expires:model::now()+30*86400,total:200*1024*1024*1024,download:28*1024*1024*1024,..Subscription::default()};
        let rules=RuleSet{name:"工作服务".into(),content:json!({"version":3,"rules":[{"domain_suffix":["example.com","example.org"]}]}),updated:model::now(),..RuleSet::default()};
        let backup = Subscription { name: "备用订阅".into(), updated:model::now()-7200,total:100*1024*1024*1024,download:62*1024*1024*1024, selected_node:Some("香港 · 01".into()), nodes: vec![
            json!({"type":"socks","tag":"香港 · 01","server":"127.0.0.1","server_port":1081}),
            json!({"type":"socks","tag":"备用 · 02","server":"127.0.0.1","server_port":1082}),
        ], ..Subscription::default() };
        state.settings.active_subscription=subscription.id.clone();state.subscriptions=vec![subscription,backup];state.rulesets=model::builtin_resources();state.rulesets.push(rules);Ok(())
    })
}

pub(super) async fn screenshot(window: &impl IsA<gtk::Window>, path: &Path) -> Result<()> {
    // Timers can run before pending layout/paint work on a busy runner. Wait
    // for complete frames so both the snapshot and following bounds checks
    // observe the allocated page, including responsive column updates.
    let clock = window.as_ref().frame_clock().context("窗口没有帧时钟")?;
    let painted = Rc::new(Cell::new(0));
    let observed = painted.clone();
    let handler = clock.connect_after_paint(move |_| observed.set(observed.get() + 1));
    clock.begin_updating();
    window.as_ref().queue_draw();
    let deadline = Instant::now() + Duration::from_secs(3);
    while painted.get() < 2 && Instant::now() < deadline {
        glib::timeout_future(Duration::from_millis(16)).await;
    }
    clock.end_updating();
    clock.disconnect(handler);
    anyhow::ensure!(painted.get() >= 2, "等待窗口布局和绘制超时");
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        match screenshot_frame(window, path) {
            Err(error)
                if matches!(
                    error.to_string().as_str(),
                    "窗口没有渲染内容" | "窗口尚未分配尺寸"
                ) && std::time::Instant::now() < deadline =>
            {
                // Under load a page can be allocated before its first painted
                // frame. Await rendering without repeating page actions.
                window.as_ref().queue_draw();
                glib::timeout_future(Duration::from_millis(50)).await;
            }
            result => return result,
        }
    }
}

fn screenshot_frame(window: &impl IsA<gtk::Window>, path: &Path) -> Result<()> {
    let window = window.as_ref();
    let width = window.width();
    let height = window.height();
    anyhow::ensure!(width > 0 && height > 0, "窗口尚未分配尺寸");
    let paintable = gtk::WidgetPaintable::new(Some(window));
    let snapshot = gtk::Snapshot::new();
    let scale = window
        .surface()
        .map(|surface| {
            if surface.find_property("scale").is_some() {
                surface.property::<f64>("scale") as f32
            } else {
                window.scale_factor() as f32
            }
        })
        .unwrap_or(1.0);
    snapshot.scale(scale, scale);
    paintable.snapshot(&snapshot, width as f64, height as f64);
    let node = snapshot.to_node().context("窗口没有渲染内容")?;
    let renderer = window.renderer().context("Wayland 渲染器不可用")?;
    let texture = renderer.render_texture(
        &node,
        Some(&gtk::graphene::Rect::new(
            0.0,
            0.0,
            width as f32 * scale,
            height as f32 * scale,
        )),
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?
    }
    texture.save_to_png(path)?;
    anyhow::ensure!(std::fs::metadata(path)?.len() > 4000, "截图内容不足");
    Ok(())
}

/// Screen position of the first log line, used to prove the view does not clip
/// the top of its text.
fn logs_bounds(ui: &Rc<Ui>) -> Result<gtk::graphene::Rect> {
    fn walk(widget: &gtk::Widget, found: &mut Option<gtk::TextView>) {
        if found.is_none()
            && let Some(view) = widget.downcast_ref::<gtk::TextView>()
        {
            *found = Some(view.clone());
        }
        let mut child = widget.first_child();
        while let Some(current) = child {
            child = current.next_sibling();
            walk(&current, found);
        }
    }
    let mut found = None;
    walk(ui.body.upcast_ref(), &mut found);
    let view = found.context("缺少日志视图")?;
    let buffer = view.buffer();
    let iter = buffer.start_iter();
    let line = view.iter_location(&iter);
    let offset = view.compute_bounds(&ui.floating).context("日志没有位置")?;
    Ok(gtk::graphene::Rect::new(
        offset.x(),
        offset.y() + line.y() as f32,
        line.width() as f32,
        line.height() as f32,
    ))
}

fn rule_controls(ui: &Rc<Ui>) -> Result<()> {
    let mut columns = [None::<f32>; 3];
    for row in descendants(&ui.body)
        .iter()
        .filter(|widget| widget.has_css_class("row-actions"))
    {
        let mut middle = None::<f32>;
        for (index, name) in ["rule-enabled", "rule-settings", "rule-delete"]
            .iter()
            .enumerate()
        {
            let control = descendants(row)
                .into_iter()
                .find(|widget| widget.widget_name() == *name)
                .context("缺少规则操作按钮")?;
            let bounds = control
                .compute_bounds(&ui.body)
                .context("规则按钮尚未布局")?;
            if let Some(x) = columns[index] {
                anyhow::ensure!((bounds.x() - x).abs() < 1.0, "规则操作列未对齐: {name}");
            } else {
                columns[index] = Some(bounds.x());
            }
            let center = bounds.y() + bounds.height() / 2.0;
            if let Some(y) = middle {
                anyhow::ensure!((center - y).abs() < 1.0, "规则操作按钮未垂直居中");
            } else {
                middle = Some(center);
            }
        }
    }
    anyhow::ensure!(columns.iter().all(Option::is_some), "缺少规则操作列");
    Ok(())
}

pub(super) async fn smoke_sequence(ui: Rc<Ui>, path: PathBuf, failed: Rc<Cell<bool>>) {
    let mut current = 0;
    let floating_y = Cell::new(None::<f32>);
    let font_size = Cell::new(None);
    let row_height = Cell::new(None);
    let normal_size = Cell::new((0, 0));
    let resources_before_reset = Rc::new(RefCell::new(None::<model::State>));
    let parent = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let app = ui.window.application().expect("application");
    let guard_app = app.clone();
    let guard_failed = failed.clone();
    glib::timeout_add_local_once(Duration::from_secs(120), move || {
        guard_failed.set(true);
        eprintln!("Wayland smoke: timed out");
        guard_app.quit();
    });
    loop {
        glib::timeout_future(Duration::from_millis(650)).await;
        let result: Result<()> = async {
            // A previous action can still be committing its result under
            // load. Wait for that work explicitly instead of adding a long
            // fixed delay to every step. In-flight checks remain inside the
            // action that starts each task.
            let deadline = Instant::now() + Duration::from_secs(5);
            while ui.jobs.get() > 0 {
                anyhow::ensure!(Instant::now() < deadline, "上一项界面操作尚未完成");
                glib::timeout_future(Duration::from_millis(16)).await;
            }
            let name = match current {
                0 => "home.png",
                1 => "subscriptions.png",
                3 => "subscriptions-selected.png",
                5 => "nodes.png",
                6 => "nodes-selected.png",
                7 => "subscriptions-returned.png",
                8 => "nodes-returned.png",
                9 => "nodes-dark.png",
                10 => "home-dark.png",
                11 => "logs.png",
                12 => "home-narrow.png",
                13 => "home-compact.png",
                14 => "home-scrolled.png",
                15 => "rules.png",
                65 => "rule-import.png",
                66 => "rule-import-dark.png",
                16 => "online-rules-editor.png",
                18 => "settings.png",
                19 => "settings-tun.png",
                20 => "subscription-import.png",
                23 => "settings-general.png",
                24 => "nodes-imported.png",
                25 => "subscriptions-large-text.png",
                26 => "subscriptions-menu.png",
                27 => "subscriptions-narrow.png",
                29 => "nodes-narrow.png",
                30 => "settings-unsaved.png",
                43 => "settings-data.png",
                45 => "settings-network.png",
                46 => "settings-detection.png",
                48 => "settings-tun-permission.png",
                59 => "nodes-fullscreen.png",
                60 => "home-fullscreen.png",
                61 => "settings-fullscreen.png",
                _ => "",
            };
            if !name.is_empty() {
                let window = if matches!(current, 65 | 66) {
                    app.windows().into_iter()
                        .find(|window| window.title().as_deref() == Some("导入规则"))
                        .context("导入规则窗口未打开")?
                } else if matches!(current, 16 | 20) {
                    app.active_window().context("编辑窗口未打开")?
                } else {
                    ui.window.clone().upcast::<gtk::Window>()
                };
                if (59..=61).contains(&current) {
                    let started = std::time::Instant::now();
                    while !ui.window.is_fullscreen() || ui.typography.density_percent() <= 100 {
                        anyhow::ensure!(
                            started.elapsed() < Duration::from_secs(3),
                            "宽屏密度未在截图前生效: {}%",
                            ui.typography.density_percent()
                        );
                        glib::timeout_future(Duration::from_millis(16)).await;
                    }
                    glib::timeout_future(Duration::from_millis(50)).await;
                }
                screenshot(&window, &parent.join(name)).await?;
            }
            if current == 0 {
                smoke_decoration_layout(&ui).await?;
                let scale = std::env::var("AEROBOX_TEST_SCALE")
                    .ok()
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(1.0);
                let surface = ui.window.surface().context("没有 Wayland surface")?;
                let actual = if surface.find_property("scale").is_some() {
                    surface.property::<f64>("scale")
                } else {
                    ui.window.scale_factor() as f64
                };
                anyhow::ensure!(
                    (actual - scale).abs() < 0.01,
                    "缩放未生效: {actual}, 预期 {scale}"
                );
                anyhow::ensure!(
                    Page::ALL.len() == 7 && !Page::ALL.iter().any(|p| p.title() == "配置"),
                    "配置页面仍存在"
                );
            }
            if current == 18 {
                settings::smoke_section(&ui, "network")?;
                ui.scroll.vadjustment().set_value(0.0);
            }
            if matches!(current, 0 | 12 | 13) {
                home::smoke_cards(&ui)?;
            }
            if current == 13 || current == 14 {
                let button = ui.home_action.borrow();
                let bounds = button
                    .as_ref()
                    .context("缺少启动按钮")?
                    .compute_bounds(&ui.floating)
                    .context("启动按钮没有位置")?;
                let height = ui.floating.height() as f32;
                anyhow::ensure!(
                    bounds.x() > ui.floating.width() as f32 - bounds.width() - 56.0
                        && bounds.x() + bounds.width() <= ui.floating.width() as f32
                        && bounds.y() > height - 110.0
                        && bounds.y() + bounds.height() <= height,
                    "启动按钮不在右下角"
                );
                if let Some(previous) = floating_y.get() {
                    anyhow::ensure!((bounds.y() - previous).abs() < 1.0, "滚动移动了启动按钮");
                }
                floating_y.set(Some(bounds.y()));
            }
            if current == 58 {
                // Restore a stable active subscription without merging the
                // backup fixtures twice; the fullscreen checks are visual only.
                let state = ui.service.snapshot();
                let selected = state
                    .subscriptions
                    .iter()
                    .find(|sub| sub.name == "日常连接")
                    .or_else(|| state.subscriptions.first())
                    .context("全屏测试缺少订阅")?
                    .id
                    .clone();
                // The preceding cache check keeps a full-length IPv6 fixture in
                // memory. Restore the neutral home state before the dark card
                // screenshot, so it tests normal wrapping rather than a
                // deliberately wide pre-wrapped address.
                ui.last_detected.replace(None);
                ui.service.update(|state| {
                    state.settings.font_size = 11;
                    state.settings.theme = "light".into();
                    state.settings.auto_detect_ip = false;
                    Ok(())
                })?;
                ui.service.select_subscription(&selected)?;
                ui.apply_font_size(11);
                apply_theme("light");
                ui.navigate(Page::Nodes);
                ui.save_window_size();
                normal_size.set((ui.window.width(), ui.window.height()));
                ui.window.fullscreen();
            }
            if current == 59 {
                nodes::smoke_fullscreen(&ui)?;
            }
            if current == 60 {
                home::smoke_cards(&ui)?;
            }
            if current == 61 {
                settings::smoke_fullscreen_settings(&ui)?;
            }
            if current == 62 {
                anyhow::ensure!(
                    !ui.window.is_fullscreen()
                        && (ui.window.width(), ui.window.height()) == normal_size.get()
                        && ui.typography.density_percent() == 100,
                    "退出全屏后没有恢复窗口尺寸和普通界面密度"
                );
                let saved = ui.service.snapshot().settings;
                anyhow::ensure!(
                    (saved.width, saved.height) == normal_size.get(),
                    "全屏改写了保存的普通窗口尺寸"
                );
            }
            match current {
                0 => {
                    let settings = ui.service.snapshot().settings;
                    anyhow::ensure!(
                        (settings.width, settings.height) == (1000, 680)
                            && (ui.window.width(), ui.window.height()) == (1000, 680),
                        "默认窗口尺寸未生效"
                    );
                    home::smoke_controls(&ui).await?;
                    ui.navigate(Page::Subscriptions);
                }
                1 => {
                    subscriptions::smoke_selection(&ui, 0, None).await?;
                    ui.import_subscription();
                }
                2 => {
                    let window = subscriptions::smoke_import_window(&ui)?;
                    screenshot(&window, &parent.join("subscription-import-default.png")).await?;
                    let form_size = (window.width(), window.height());
                    apply_theme("dark");
                    glib::timeout_future(Duration::from_millis(80)).await;
                    anyhow::ensure!(window.has_css_class("dark"), "导入弹窗没有跟随深色模式");
                    let source = descendants(&window).into_iter().find_map(|widget| widget.downcast::<gtk::TextView>().ok()).context("缺少订阅输入框")?;
                    source.buffer().set_text("https://subscription.example.test/link");
                    screenshot(&window, &parent.join("subscription-import-dark.png")).await?;
                    apply_theme("light");
                    window.close();
                    smoke_form_dialogs(&ui, &parent, form_size).await?;
                }
                3 => {
                    subscriptions::smoke_selection(&ui, 0, Some(1)).await?;
                }
                4 => {
                    subscriptions::smoke_selection(&ui, 1, None).await?;
                    ui.navigate(Page::Nodes);
                }
                5 => {
                    nodes::smoke_delay_colors(&ui)?;
                    ui.service.set_routing_mode("global")?;
                    nodes::smoke_nodes(&ui, "备用订阅", 2, Some("香港 · 01"), Some(1))?;
                    nodes::smoke_delay_colors(&ui)?;
                }
                6 => {
                    nodes::smoke_nodes(&ui, "备用订阅", 2, Some("备用 · 02"), None)?;
                    anyhow::ensure!(
                        ui.service.snapshot().settings.routing_mode == "global",
                        "选择节点改变了模式"
                    );
                    ui.navigate(Page::Subscriptions);
                    subscriptions::smoke_selection(&ui, 1, Some(0)).await?;
                }
                7 => {
                    subscriptions::smoke_selection(&ui, 0, None).await?;
                    ui.navigate(Page::Nodes);
                }
                8 => {
                    nodes::smoke_delay_failure(&ui)?;
                    nodes::smoke_nodes(&ui, "日常连接", 6, Some("日本 · 01"), None)?;
                    nodes::smoke_test_node(&ui, 0).await?;
                    nodes::smoke_selection_navigation(&ui).await?;
                    apply_theme("dark");
                }
                9 => home::smoke_ip_cache(&ui).await?,
                10 => {
                    // The loop captures its screenshot before running a step,
                    // so home-dark.png above shows the page as step 9 left it.
                    anyhow::ensure!(ui.page.get() == Page::Home, "深色首页截图不在首页");
                    home::smoke_home_action_theme(&ui, true)?;
                    home::smoke_running_action(&ui, &parent.join("home-dark-running.png")).await?;
                    // Real log text with descenders and digits, so the layout
                    // check can see whether the first line is clipped.
                    ui.service.log("info: 出口 IP 已更新 (IPv4 203.0.113.7)");
                    ui.service.log("debug: rule-set 中国大陆域名 gzip=ok");
                    ui.navigate(Page::Logs);
                }
                11 => {
                    let bounds = logs_bounds(&ui)?;
                    anyhow::ensure!(bounds.y() >= 0.0, "日志首行被裁切: {bounds:?}");
                    apply_theme("light");
                    ui.navigate(Page::Home);
                    home::smoke_home_action_theme(&ui, false)?;
                    ui.window.set_default_size(790, 800);
                }
                12 => ui.window.set_default_size(700, 600),
                13 => {
                    let adjustment = ui.scroll.vadjustment();
                    adjustment.set_value(adjustment.upper());
                }
                14 => {
                    let settings = ui.service.snapshot().settings;
                    anyhow::ensure!(
                        (settings.width, settings.height) == (700, 600)
                            && (ui.window.width(), ui.window.height()) == (700, 600),
                        "窗口调整后没有保存实际大小: 配置 {}x{}，窗口 {}x{}",
                        settings.width,
                        settings.height,
                        ui.window.width(),
                        ui.window.height()
                    );
                    ui.window.set_default_size(1000, 680);
                    ui.observe_window_size();
                    ui.navigate(Page::Rules);
                }
                15 => {
                    rule_controls(&ui)?;
                    let settings = ui.service.snapshot().settings;
                    anyhow::ensure!(
                        (settings.width, settings.height) == (1000, 680)
                            && (ui.window.width(), ui.window.height()) == (1000, 680),
                        "恢复默认窗口大小后没有持久化"
                    );
                    let rule = ui
                        .service
                        .snapshot()
                        .rulesets
                        .into_iter()
                        .find(|r| r.id == model::BUILTIN_DOMESTIC_ID)
                        .unwrap();
                    editors::ruleset(&ui.window, ui.service.clone(), rule, ui.saved());
                }
                16 => editors::smoke_ruleset(&ui.window, ui.service.clone(), false)?,
                17 => {
                    editors::smoke_ruleset(&ui.window, ui.service.clone(), true)?;
                    ui.navigate(Page::Settings);
                }
                18 => {
                    font_size.set(
                        ui.window
                            .pango_context()
                            .font_description()
                            .map(|f| f.size()),
                    );
                    row_height.set(settings::smoke_row_height(&ui));
                    settings::smoke_settings(&ui, false)?;
                }
                19 => {
                    settings::smoke_settings(&ui, true)?;
                    let larger = ui
                        .window
                        .pango_context()
                        .font_description()
                        .map(|f| f.size());
                    anyhow::ensure!(
                        matches!((font_size.get(),larger),(Some(before),Some(after)) if after>before),
                        "字体大小没有实时生效"
                    );
                    // Text alone is not enough: rows and controls must grow with
                    // it, otherwise larger type just gets cramped in place.
                    let after_row = settings::smoke_row_height(&ui);
                    anyhow::ensure!(
                        matches!((row_height.get(),after_row),(Some(before),Some(after)) if after > before),
                        "字体变大后行高没有跟随: {:?} -> {:?}",
                        row_height.get(),
                        after_row
                    );
                    anyhow::ensure!(
                        ui.split.min_sidebar_width() > 180.0,
                        "预览大字号没有同步放宽侧栏"
                    );
                    ui.navigate(Page::Subscriptions);
                    ui.import_subscription();
                }
                20 | 21 => subscriptions::smoke_import(&ui, current - 19)?,
                22 => {
                    subscriptions::smoke_import(&ui, 3)?;
                    subscriptions::smoke_selection(&ui, 0, None).await?;
                    let state = ui.service.snapshot();
                    anyhow::ensure!(
                        state.subscriptions[0].selected_node.as_deref() == Some("日本 · 01"),
                        "导入订阅改变了原有节点选择"
                    );
                    ui.navigate(Page::Settings);
                    settings::smoke_section(&ui, "general")?;
                }
                23 => {
                    settings::smoke_general(&ui)?;
                    ui.navigate(Page::Subscriptions);
                    subscriptions::smoke_selection(&ui, 0, Some(2)).await?;
                    ui.navigate(Page::Nodes);
                }
                24 => {
                    nodes::smoke_nodes(&ui, "导入检查", 1, None, None)?;
                    startup::smoke_recovery()?;
                    ui.navigate(Page::Subscriptions);
                }
                25 => {
                    subscriptions::smoke_selection(&ui, 2, None).await?;
                    subscriptions::smoke_menu(&ui, true)?;
                }
                26 => {
                    subscriptions::smoke_selection(&ui, 2, None).await?;
                    subscriptions::smoke_menu(&ui, false)?;
                    ui.window.set_default_size(600, 720);
                }
                27 => {
                    subscriptions::smoke_selection(&ui, 2, None).await?;
                    let id = ui.service.snapshot().subscriptions[0].id.clone();
                    ui.service.select_subscription(&id)?;
                    ui.navigate(Page::Nodes);
                    anyhow::ensure!(
                        ui.subscription_revision.get() == ui.service.subscription_revision(),
                        "新节点页没有记录已显示的订阅版本，定时刷新会重置滚动位置"
                    );
                }
                28 => {
                    let adjustment = ui.scroll.vadjustment();
                    adjustment.set_value(adjustment.upper());
                }
                29 => {
                    nodes::smoke_nodes(&ui, "日常连接", 6, Some("日本 · 01"), None)?;
                    nodes::smoke_floating_action(&ui)?;
                    nodes::smoke_test_node(&ui, 0).await?;
                    ui.window.set_default_size(1000, 680);
                    ui.navigate(Page::Settings);
                    settings::smoke_unsaved(&ui, None).await?;
                }
                30 => {
                    settings::smoke_save_bounds(&ui)?;
                    settings::smoke_unsaved(&ui, Some("cancel")).await?;
                }
                31 => {
                    anyhow::ensure!(
                        !settings::SettingsPanel::smoke_has_prompt(&ui),
                        "继续编辑后确认框未关闭"
                    );
                    anyhow::ensure!(ui.page.get() == Page::Settings, "继续编辑离开了设置页");
                    ui.confirm_discard_settings({
                        let ui = ui.clone();
                        move || ui.navigate(Page::Nodes)
                    });
                    anyhow::ensure!(
                        settings::SettingsPanel::smoke_has_prompt(&ui),
                        "继续编辑后无法再次请求离开"
                    );
                }
                32 => {
                    settings::smoke_unsaved(&ui, Some("discard")).await?;
                }
                33 => {
                    anyhow::ensure!(
                        ui.page.get() == Page::Nodes,
                        "放弃更改后未离开: page={:?} pending={} prompt={} jobs={}",
                        ui.page.get(),
                        ui.pending_leave.borrow().is_some(),
                        ui.settings_prompt.borrow().is_some(),
                        ui.jobs.get()
                    );
                    ui.navigate(Page::Settings);
                    settings::smoke_restored(&ui)?;
                    settings::smoke_unsaved(&ui, None).await?;
                }
                34 => {
                    settings::smoke_unsaved(&ui, Some("save")).await?;
                    anyhow::ensure!(ui.page.get() == Page::Settings, "保存完成前提前离开");
                }
                35 => {
                    anyhow::ensure!(ui.jobs.get() == 0, "保存并离开尚未完成");
                    anyhow::ensure!(
                        ui.page.get() == Page::Nodes,
                        "保存并离开未切页: page={:?} jobs={} pending={} panel={}",
                        ui.page.get(),
                        ui.jobs.get(),
                        ui.pending_leave.borrow().is_some(),
                        ui.settings_panel.borrow().is_some()
                    );
                    anyhow::ensure!(
                        ui.service.snapshot().settings.font_size == model::FONT_SIZE_MIN,
                        "保存并离开未持久化"
                    );
                }
                36 => {
                    ui.navigate(Page::Settings);
                    settings::smoke_edit(&ui)?;
                    anyhow::ensure!(
                        ui.confirm_close() == glib::Propagation::Stop,
                        "未保存时允许关闭窗口"
                    );
                    anyhow::ensure!(ui.window.is_visible(), "未保存时直接关闭了窗口");
                    settings::smoke_unsaved(&ui, Some("cancel")).await?;
                }
                37 => {
                    ui.navigate(Page::Nodes);
                    settings::smoke_unsaved(&ui, Some("discard")).await?;
                }
                38 => {
                    anyhow::ensure!(
                        ui.page.get() == Page::Nodes,
                        "放弃更改后未离开: page={:?} pending={} prompt={} jobs={}",
                        ui.page.get(),
                        ui.pending_leave.borrow().is_some(),
                        ui.settings_prompt.borrow().is_some(),
                        ui.jobs.get()
                    );
                    ui.navigate(Page::Settings);
                    settings::smoke_restored(&ui)?;
                    settings::smoke_data_action(&ui, 0).await?;
                    resources_before_reset.replace(None);
                }
                40 => settings::smoke_data_action(&ui, 1).await?,
                41 => {
                    resources_before_reset.replace(Some(ui.service.snapshot()));
                    settings::smoke_data_action(&ui, 2).await?;
                }
                42 => {
                    settings::smoke_data_action(&ui, 3).await?;
                    let state = ui.service.snapshot();
                    let before = resources_before_reset
                        .borrow()
                        .clone()
                        .context("没有恢复默认前的资源快照")?;
                    anyhow::ensure!(
                        serde_json::to_value(&state.subscriptions)?
                            == serde_json::to_value(&before.subscriptions)?
                            && serde_json::to_value(&state.rulesets)?
                                == serde_json::to_value(&before.rulesets)?
                            && state.settings.active_subscription
                                == before.settings.active_subscription
                            && (state.settings.width, state.settings.height)
                                == (before.settings.width, before.settings.height),
                        "恢复默认改变了订阅、规则、当前选择或窗口尺寸"
                    );
                    anyhow::ensure!(
                        state.settings.routing_mode == before.settings.routing_mode,
                        "恢复默认错误地改变了首页运行模式"
                    );
                    let adjustment = ui.scroll.vadjustment();
                    adjustment.set_value(adjustment.upper());
                }
                43 => {
                    let adjustment = ui.scroll.vadjustment();
                    adjustment.set_value(0.0);
                    settings::smoke_data_action(&ui, 4).await?;
                }
                44 => {
                    settings::smoke_restored(&ui)?;
                    let state = ui.service.snapshot();
                    let before = resources_before_reset
                        .borrow()
                        .clone()
                        .context("没有合并恢复前的资源快照")?;
                    anyhow::ensure!(
                        state.subscriptions.len() == before.subscriptions.len() * 2
                            && state.rulesets.len() == before.rulesets.len() * 2
                            && state.settings.direct_dns == "tcp://223.5.5.5:5353"
                            && state.settings.active_subscription
                                != before.settings.active_subscription
                            && state.settings.routing_mode == "global",
                        "备份没有正确合并或恢复设置"
                    );
                    settings::smoke_section(&ui, "network")?;
                }
                45 => {
                    settings::smoke_network(&ui).await?;
                    settings::smoke_section(&ui, "testing")?;
                }
                47 => {
                    settings::smoke_section(&ui, "tun")?;
                }
                49 => {
                    settings::smoke_tun_settings(&ui).await?;
                }
                50..=56 => settings::smoke_autostart(&ui, current - 50).await?,
                57 => subscriptions::smoke_dialog_release(&ui)?,
                59 => ui.navigate(Page::Home),
                60 => ui.navigate(Page::Settings),
                61 => {
                    ui.window.unfullscreen();
                }
                62 => {
                    ui.window.set_default_size(1000, 680);
                    ui.navigate(Page::Nodes);
                }
                63 => smoke_resize_boundaries(&ui).await?,
                64 => {
                    ui.navigate(Page::Rules);
                    let add = descendants(&ui.body)
                        .into_iter()
                        .filter_map(|widget| widget.downcast::<gtk::Button>().ok())
                        .find(|button| button.widget_name() == "rule-import")
                        .context("缺少导入规则入口")?;
                    add.emit_clicked();
                    let window = editors::smoke_rule_import(&ui.window)?;
                    let add = descendants(&ui.body)
                        .into_iter()
                        .filter_map(|widget| widget.downcast::<gtk::Button>().ok())
                        .find(|button| button.widget_name() == "rule-import")
                        .context("规则工具栏按钮丢失")?;
                    anyhow::ensure!(
                        add.has_css_class("compact-action")
                            && add.has_css_class("secondary-action")
                            && !add.has_css_class("suggested-action"),
                        "规则导入入口层级错误"
                    );
                    window.present();
                }
                65 => {
                    apply_theme("dark");
                }
                66 => {
                    let window = app.windows().into_iter()
                        .find(|window| window.title().as_deref() == Some("导入规则"))
                        .context("导入规则窗口未保留")?;
                    apply_theme("light");
                    window.close();
                    ui.window.present();
                }
                _ => {}
            }
            Ok(())
        }.await;
        if let Err(error) = result {
            eprintln!("Wayland smoke step {current}: {error:#}");
            if let Err(screenshot_error) = screenshot(
                &ui.window.clone().upcast::<gtk::Window>(),
                &parent.join("smoke-failure.png"),
            )
            .await
            {
                eprintln!("failure screenshot: {screenshot_error:#}");
            }
            failed.set(true);
            app.quit();
            return;
        }
        if current == 66 {
            let clipboard = ui.window.clipboard();
            clipboard.set_text("AeroBox Wayland 剪贴板测试");
            let app = app.clone();
            let failed = failed.clone();
            clipboard.read_text_async(None::<&gio::Cancellable>,move |result| {
                if !matches!(result,Ok(Some(ref text)) if text=="AeroBox Wayland 剪贴板测试") {failed.set(true);eprintln!("Clipboard roundtrip failed");}
                else {println!("Wayland smoke: selection, cards, settings, fullscreen scaling, import and clipboard passed");}
                app.quit();
            });
            return;
        }
        current += 1;
    }
}

async fn smoke_form_dialogs(ui: &Rc<Ui>, path: &Path, size: (i32, i32)) -> Result<()> {
    let app = ui.window.application().context("缺少应用")?;
    for (file, title) in [
        ("subscription-edit", "编辑订阅"),
        ("rule-edit", "编辑规则"),
        ("rule-import-local", "导入规则"),
    ] {
        let state = ui.service.snapshot();
        match file {
            "subscription-edit" => {
                let mut item = state.subscriptions[0].clone();
                item.source = "https://subscription.example.test/link".into();
                editors::subscription(&ui.window, ui.service.clone(), item, ui.saved());
            }
            "rule-edit" => editors::ruleset(
                &ui.window,
                ui.service.clone(),
                state.rulesets[0].clone(),
                ui.saved(),
            ),
            _ => editors::ruleset(
                &ui.window,
                ui.service.clone(),
                RuleSet::default(),
                ui.saved(),
            ),
        }
        let window = app
            .windows()
            .into_iter()
            .find(|window| window.title().as_deref() == Some(title))
            .with_context(|| format!("{title}未打开"))?;
        screenshot(&window, &path.join(format!("{file}.png"))).await?;
        anyhow::ensure!(
            window.pango_context().font_description()
                == ui.window.pango_context().font_description(),
            "{title}字体没有与主窗口同步"
        );
        anyhow::ensure!(
            (window.width(), window.height()) == size,
            "{title}尺寸与导入订阅不同: {}x{} / {}x{}",
            window.width(),
            window.height(),
            size.0,
            size.1
        );
        let widgets = descendants(&window);
        let form = widgets
            .iter()
            .find(|widget| widget.has_css_class("dialog-form"))
            .context("缺少表单容器")?;
        let bounds = form.compute_bounds(&window).context("表单未布局")?;
        anyhow::ensure!(
            bounds.x() >= 19.0 && bounds.x() + bounds.width() <= window.width() as f32 - 19.0,
            "{title}表单越过统一边距"
        );
        if title == "编辑订阅" {
            let toggle = widgets
                .iter()
                .find_map(|widget| widget.downcast_ref::<adw::SwitchRow>())
                .context("订阅设置缺少自动更新")?;
            let interval = widgets
                .iter()
                .filter_map(|widget| widget.downcast_ref::<gtk::Entry>())
                .find(|entry| entry.placeholder_text().as_deref() == Some("更新间隔（分钟）"))
                .context("订阅设置缺少更新间隔")?;
            toggle.set_active(false);
            anyhow::ensure!(
                !interval.parent().unwrap().is_visible(),
                "关闭更新后仍显示间隔"
            );
            toggle.set_active(true);
            anyhow::ensure!(
                interval.parent().unwrap().is_visible(),
                "开启更新后未显示间隔"
            );
        }
        let source_schemes: Vec<_> = widgets
            .iter()
            .filter_map(|widget| widget.downcast_ref::<sourceview::View>())
            .filter_map(|view| view.buffer().downcast::<sourceview::Buffer>().ok())
            .map(|buffer| {
                let scheme = buffer.style_scheme().map(|scheme| scheme.id());
                (buffer, scheme)
            })
            .collect();
        apply_theme("dark");
        for (buffer, previous) in source_schemes {
            anyhow::ensure!(
                buffer.style_scheme().map(|scheme| scheme.id()) != previous,
                "{title}源码配色未跟随深色模式"
            );
        }
        screenshot(&window, &path.join(format!("{file}-dark.png"))).await?;
        anyhow::ensure!(window.has_css_class("dark"), "{title}未跟随深色模式");
        window.close();
        apply_theme("light");
    }
    Ok(())
}

async fn smoke_resize_boundaries(ui: &Rc<Ui>) -> Result<()> {
    let saved_font_size = ui.service.snapshot().settings.font_size;
    // The sidebar grows at the wide breakpoint. Repeated frames must keep the
    // new density, rather than using the narrower content to switch it back.
    for (width, density) in [(1224, 100), (1232, 112), (1224, 100), (1000, 100)] {
        ui.window.set_default_size(width, 680);
        let start = Instant::now();
        while ui.window.width() != width || ui.typography.density_percent() != density {
            anyhow::ensure!(
                start.elapsed() < Duration::from_secs(3),
                "缩放边界没有完成布局"
            );
            glib::timeout_future(Duration::from_millis(16)).await;
        }
        for _ in 0..20 {
            glib::timeout_future(Duration::from_millis(16)).await;
            anyhow::ensure!(
                ui.typography.density_percent() == density,
                "缩放在临界宽度 {width} 来回跳动"
            );
        }
    }
    // Font previews must update the sidebar even without a density change.
    for size in [model::FONT_SIZE_MIN, model::FONT_SIZE_MAX, 11] {
        ui.apply_font_size(size);
        glib::timeout_future(Duration::from_millis(80)).await;
        anyhow::ensure!(
            (ui.split.min_sidebar_width() - sidebar_width(f64::from(size))).abs() < 0.1,
            "修改字号没有同步侧栏宽度"
        );
        let actual = ui
            .window
            .pango_context()
            .font_description()
            .context("缺少窗口字体")?;
        let units_per_point = if actual.is_size_absolute() {
            f64::from(
                gtk::Settings::default()
                    .context("缺少 GTK 设置")?
                    .gtk_xft_dpi(),
            ) / 1024.0
                / 72.0
        } else {
            1.0
        };
        anyhow::ensure!(
            (actual.size() as f64 / gtk::pango::SCALE as f64 - f64::from(size) * units_per_point)
                .abs()
                < 0.1,
            "普通窗口字体与用户设置不符"
        );
    }
    anyhow::ensure!(
        ui.service.snapshot().settings.font_size == saved_font_size,
        "预览改写了保存的字号"
    );
    let desktop = gio::Settings::new("org.gnome.desktop.interface");
    let original_font = desktop.string("font-name");
    let original_scale = desktop.double("text-scaling-factor");
    ui.apply_font_size(0);
    for (name, scale, expected_px) in [
        ("Sans 15", 1.0, 20.0),
        ("Sans 15", 1.25, 25.0),
        ("Sans 20px", 1.25, 20.0),
    ] {
        desktop.set_string("font-name", name)?;
        desktop.set_double("text-scaling-factor", scale)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let font = ui
                .window
                .pango_context()
                .font_description()
                .context("缺少系统字体")?;
            let actual_px = f64::from(font.size()) / f64::from(gtk::pango::SCALE)
                * if font.is_size_absolute() {
                    1.0
                } else {
                    96.0 * scale / 72.0
                };
            if (actual_px - expected_px).abs() < 0.1 {
                break;
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "系统字体或文字缩放未生效: {name}, scale={scale}, px={actual_px}"
            );
            glib::timeout_future(Duration::from_millis(16)).await;
        }
        anyhow::ensure!(
            (ui.split.min_sidebar_width() - sidebar_width(expected_px * 72.0 / 96.0)).abs() < 0.1,
            "系统字号变化没有同步侧栏宽度"
        );
    }
    let font = ui
        .window
        .pango_context()
        .font_description()
        .context("缺少系统字体")?;
    anyhow::ensure!(font.family().as_deref() == Some("Sans"), "系统字体族未生效");
    desktop.set_string("font-name", &original_font)?;
    desktop.set_double("text-scaling-factor", original_scale)?;
    ui.apply_font_size(saved_font_size);
    Ok(())
}

async fn smoke_decoration_layout(ui: &Rc<Ui>) -> Result<()> {
    let headers = descendants(&ui.window)
        .into_iter()
        .filter_map(|widget| widget.downcast::<adw::HeaderBar>().ok())
        .filter(|header| header.has_css_class("app-header"))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        headers.len() == 1,
        "找不到主窗口标题栏: count={}",
        headers.len()
    );
    let header = &headers[0];
    anyhow::ensure!(
        header.decoration_layout().is_none(),
        "标题栏覆盖了系统窗口按钮布局"
    );
    let controls = descendants(header)
        .into_iter()
        .filter_map(|widget| widget.downcast::<gtk::WindowControls>().ok())
        .filter(|controls| controls.side() == gtk::PackType::End)
        .collect::<Vec<_>>();
    anyhow::ensure!(controls.len() == 1, "主窗口缺少右侧窗口按钮");
    let buttons = descendants(&controls[0])
        .into_iter()
        .filter_map(|widget| widget.downcast::<gtk::Button>().ok())
        .filter(|button| button.is_visible())
        .collect::<Vec<_>>();
    anyhow::ensure!(buttons.len() == 1, "窗口按钮不是仅关闭: {}", buttons.len());
    let icon = buttons[0]
        .child()
        .and_then(|child| child.downcast::<gtk::Image>().ok())
        .and_then(|image| image.icon_name());
    anyhow::ensure!(
        icon.as_deref() == Some("window-close-symbolic"),
        "唯一窗口按钮不是关闭: {icon:?}"
    );
    let desktop = gio::Settings::new("org.gnome.desktop.wm.preferences");
    for (layout, count) in [("menu:minimize,maximize,close", 3), (":close", 1)] {
        desktop.set_string("button-layout", layout)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let buttons = descendants(&controls[0])
                .into_iter()
                .filter_map(|widget| widget.downcast::<gtk::Button>().ok())
                .filter(|button| button.is_visible())
                .count();
            if buttons == count {
                break;
            }
            anyhow::ensure!(
                std::time::Instant::now() < deadline,
                "桌面窗口按钮变化未实时同步: {layout}, buttons={buttons}"
            );
            glib::timeout_future(Duration::from_millis(16)).await;
        }
    }
    Ok(())
}
