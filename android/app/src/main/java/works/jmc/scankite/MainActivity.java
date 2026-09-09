/*
 * scankite — Copyright (C) 2026 amirmahdavi2023
 * Licensed under the GNU General Public License v3.0 or later. See LICENSE.
 */
package works.jmc.scankite;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * One screen. Press the button, wait, get configs you can paste into a client.
 *
 * <p>Everything the app knows how to say is a string resource, in both languages, and the switch
 * is in the app rather than only in the system settings — the people this is for often keep their
 * phone in one language and want the tool in the other.
 */
public final class MainActivity extends Activity implements Engine.Watcher {

    private static final String PREFS = "scankite";
    private static final String KEY_LANGUAGE = "language";
    private static final String KEY_TAG = "tag";

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final List<Engine.Result> results = new ArrayList<>();

    private TextView statusTitle;
    private TextView statusBody;
    private ProgressBar progress;
    private Button action;
    private LinearLayout list;
    private LinearLayout bottom;
    private ScrollView scroll;

    private Engine engine;
    private Thread worker;
    private boolean running;

    // ---------------------------------------------------------------- language

    @Override protected void attachBaseContext(Context base) {
        SharedPreferences prefs = base.getSharedPreferences(PREFS, MODE_PRIVATE);
        String language = prefs.getString(KEY_LANGUAGE, "");
        if (language.isEmpty()) {
            super.attachBaseContext(base);
            return;
        }
        Locale locale = new Locale(language);
        Locale.setDefault(locale);
        Configuration configuration = new Configuration(base.getResources().getConfiguration());
        configuration.setLocale(locale);
        configuration.setLayoutDirection(locale);
        super.attachBaseContext(base.createConfigurationContext(configuration));
    }

    private void toggleLanguage() {
        SharedPreferences prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        String current = prefs.getString(KEY_LANGUAGE, "");
        if (current.isEmpty()) {
            // Nothing chosen yet, so the app is following the system. Switch to the other one.
            current = Locale.getDefault().getLanguage().startsWith("fa") ? "fa" : "en";
        }
        prefs.edit().putString(KEY_LANGUAGE, "fa".equals(current) ? "en" : "fa").apply();
        recreate();
    }

    // ---------------------------------------------------------------- lifecycle

    @Override protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        setContentView(R.layout.activity_main);

        statusTitle = findViewById(R.id.status_title);
        statusBody = findViewById(R.id.status_body);
        progress = findViewById(R.id.progress);
        action = findViewById(R.id.action);
        list = findViewById(R.id.results);
        bottom = findViewById(R.id.bottom);
        scroll = findViewById(R.id.scroll);

        action.setOnClickListener(view -> { if (running) stop(); else start(); });
        findViewById(R.id.language).setOnClickListener(view -> toggleLanguage());
        findViewById(R.id.settings).setOnClickListener(view -> settings());
        findViewById(R.id.copy_all).setOnClickListener(view -> copyAll(false));
        findViewById(R.id.copy_sub).setOnClickListener(view -> copyAll(true));
    }

    @Override protected void onDestroy() {
        if (engine != null) engine.cancel();
        super.onDestroy();
    }

    // ---------------------------------------------------------------- running

    private void start() {
        running = true;
        results.clear();
        list.removeAllViews();
        bottom.setVisibility(View.GONE);
        action.setText(R.string.stop);
        progress.setVisibility(View.VISIBLE);
        progress.setProgress(0);
        statusTitle.setText(R.string.phase_1);
        statusBody.setText("");

        engine = new Engine(getFilesDir(), this);
        worker = new Thread(engine::run, "scan");
        worker.setDaemon(true);
        worker.start();
    }

    private void stop() {
        if (engine != null) engine.cancel();
        running = false;
        action.setText(results.isEmpty() ? R.string.start : R.string.again);
        progress.setVisibility(View.GONE);
    }

    @Override public void phase(int step, int of, String detail) {
        ui.post(() -> {
            progress.setProgress(step);
            int title;
            switch (step) {
                case 1: title = R.string.phase_1; break;
                case 2: title = R.string.phase_2; break;
                case 3: title = R.string.phase_3; break;
                default: title = R.string.phase_4;
            }
            statusTitle.setText(title);
            statusBody.setText(detail == null ? "" : detail);
        });
    }

    @Override public void found(Engine.Result result) {
        ui.post(() -> {
            results.add(result);
            addRow(result, results.size());
            bottom.setVisibility(View.VISIBLE);
            statusTitle.setText(getString(results.size() == 1
                    ? R.string.found_one : R.string.found_many, results.size()));
            scroll.post(() -> scroll.fullScroll(View.FOCUS_DOWN));
        });
    }

    @Override public void done(List<Engine.Result> finished, String summary) {
        ui.post(() -> {
            running = false;
            progress.setVisibility(View.GONE);
            action.setText(R.string.again);

            if (!results.isEmpty()) {
                statusTitle.setText(getString(results.size() == 1
                        ? R.string.found_one : R.string.found_many, results.size()));
                statusBody.setText("ok-fallback-ranges".equals(summary)
                        ? getString(R.string.ranges_fallback) : getString(R.string.proved));
                // Redrawn in ranked order, so the fastest is not simply whichever finished first.
                list.removeAllViews();
                sortResults();
                for (int i = 0; i < results.size(); i++) addRow(results.get(i), i + 1);
                return;
            }

            if ("no-pool".equals(summary)) {
                statusTitle.setText(R.string.empty_pool_title);
                statusBody.setText(R.string.empty_pool_body);
            } else if ("no-edge".equals(summary)) {
                statusTitle.setText(R.string.empty_edge_title);
                statusBody.setText(R.string.empty_edge_body);
            } else {
                statusTitle.setText(R.string.empty_none_title);
                statusBody.setText(R.string.empty_none_body);
            }
        });
    }

    private void sortResults() {
        java.util.Collections.sort(results, (a, b) -> Long.compare(a.millis, b.millis));
    }

    // ---------------------------------------------------------------- results

    private void addRow(Engine.Result result, int rank) {
        View row = LayoutInflater.from(this).inflate(R.layout.row_result, list, false);
        ((TextView) row.findViewById(R.id.rank)).setText(String.valueOf(rank));
        ((TextView) row.findViewById(R.id.origin)).setText(result.origin);
        ((TextView) row.findViewById(R.id.detail))
                .setText(getString(R.string.via, result.edge));
        ((TextView) row.findViewById(R.id.latency))
                .setText(getString(R.string.ms, (int) result.millis));
        row.findViewById(R.id.copy).setOnClickListener(view -> {
            copy(Exporter.clean(result.config, tag(), rank).toUri());
            toast(getString(R.string.copied));
        });
        list.addView(row);
    }

    private void copyAll(boolean asSubscription) {
        List<ProxyConfig> configs = new ArrayList<>();
        for (Engine.Result result : results) configs.add(result.config);
        copy(asSubscription
                ? Exporter.encoded(configs, tag())
                : Exporter.subscription(configs, tag()));
        toast(getString(R.string.copied_all, configs.size()));
    }

    private void copy(String text) {
        ClipboardManager clipboard =
                (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard != null) clipboard.setPrimaryClip(ClipData.newPlainText("scankite", text));
    }

    private void toast(String message) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
    }

    // ---------------------------------------------------------------- settings

    private String tag() {
        return getSharedPreferences(PREFS, MODE_PRIVATE).getString(KEY_TAG, "");
    }

    private void settings() {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (20 * getResources().getDisplayMetrics().density);
        box.setPadding(pad, pad / 2, pad, 0);

        TextView label = new TextView(this);
        label.setText(R.string.tag_label);
        label.setTextSize(14);
        box.addView(label);

        EditText field = new EditText(this);
        field.setSingleLine(true);
        field.setInputType(InputType.TYPE_CLASS_TEXT);
        field.setHint(R.string.tag_hint);
        field.setText(tag());
        box.addView(field);

        TextView note = new TextView(this);
        note.setText(R.string.tag_note);
        note.setTextSize(12);
        note.setPadding(0, pad / 3, 0, 0);
        box.addView(note);

        new AlertDialog.Builder(this)
                .setTitle(R.string.settings)
                .setView(box)
                .setPositiveButton(R.string.save, (dialog, which) ->
                        getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                                .putString(KEY_TAG, field.getText().toString().trim()).apply())
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }
}
