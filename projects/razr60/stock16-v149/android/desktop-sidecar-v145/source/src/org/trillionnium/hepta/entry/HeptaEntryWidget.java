package org.trillionnium.hepta.entry;

import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.Context;
import android.widget.RemoteViews;

/** Static entry widget: no timer, backend query, worker, turn or persistent process. */
public final class HeptaEntryWidget extends AppWidgetProvider {
    @Override public void onUpdate(Context context, AppWidgetManager manager, int[] ids) {
        for (int id : ids) {
            RemoteViews views = new RemoteViews(context.getPackageName(), R.layout.hepta_entry_widget);
            PendingIntent open = PendingIntent.getActivity(context, id, EntryIntents.entry(context),
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            views.setOnClickPendingIntent(R.id.entry_container, open);
            manager.updateAppWidget(id, views);
        }
    }
}
