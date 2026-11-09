package org.trillionnium.hepta.local;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** One bounded fact about the source of the current immutable catalogue page.
 *
 * This is not a dispatched effect or an instruction. Initial ranking has already
 * run; tool_completed specifically means a model-issued find_app completed.
 * A successful query replaces this fact, rather than growing prompt history.
 */
public final class AppSearchProvenance {
    private final AppCatalogueRanker.Page page;
    private final int sourceStep;

    private AppSearchProvenance(AppCatalogueRanker.Page page,int sourceStep){
        if(page==null)throw new IllegalArgumentException("app search page required");
        this.page=page;this.sourceStep=sourceStep;
    }

    public static AppSearchProvenance initialRanking(AppCatalogueRanker.Page page){
        return new AppSearchProvenance(page,0);
    }

    public static AppSearchProvenance completedFindApp(AppCatalogueRanker.Page page,ActionDecision action,
                                                      int sourceStep,boolean accepted,boolean dispatched){
        if(!accepted||dispatched||sourceStep<=0||action==null||!ActionPolicy.isReadOnlyDiscovery(action))
            throw new IllegalArgumentException("completed read-only model query required");
        if(page==null||!page.query.equals(action.query)||page.offset!=action.offset)
            throw new IllegalArgumentException("app search result differs from issued query/offset");
        return new AppSearchProvenance(page,sourceStep);
    }

    /** Mandatory prompt facts: never abbreviated by the optional recent-history budget. */
    public Map<String,Object> project(AppCatalogueRanker.Page current,int shown){
        // Identity binds the query, offset, full catalogue SHA and exact result page.
        // Even an equivalent re-query must acquire its own completion provenance.
        if(current!=page)throw new IllegalArgumentException("app search provenance belongs to another page");
        int next=current.nextOffset(shown);
        Map<String,Object> result=new LinkedHashMap<String,Object>();
        result.put("query",current.query);result.put("offset",current.offset);
        result.put("matches",current.matchingApps);result.put("total_apps",current.totalApps);
        result.put("next_offset",next<0?null:Integer.valueOf(next));
        result.put("source",sourceStep==0?"initial_ranking":"model_find_app");
        result.put("source_step",sourceStep==0?null:Integer.valueOf(sourceStep));
        result.put("model_issued",sourceStep>0);result.put("tool_completed",sourceStep>0);
        result.put("catalogue_sha256",current.catalogueSha256);
        return Collections.unmodifiableMap(result);
    }
}
