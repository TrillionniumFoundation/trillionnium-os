package org.trillionnium.hepta.local;
import java.util.*;

/** Historical source replay, never reused as a current product pass. */
public final class PreviousNotesEditorReplay {
    public static void main(String[] args){
        int checks=0;List<String> names=new ArrayList<String>();
        Map<String,String> hashes=new LinkedHashMap<String,String>();hashes.put("base",NotesCompletionEvidence.OBSERVED_BASE_APK_SHA256);
        NotesCompletionEvidence.Installed installed=new NotesCompletionEvidence.Installed(NotesCompletionEvidence.NOTES,10382,hashes);
        for(int i=0;i<5;i++){
            NotesCompletionEvidence.Frame f=PreviousCompletionBridge.copy(CapturedNotesFixtures.get(i));
            NotesCompletionEvidence.BodyEvidence e=NotesCompletionEvidence.editor(f,CapturedNotesFixtures.BODIES[i],installed);
            checks++;if(i<4?e.matched:!e.matched)throw new AssertionError("old source outcome differs: "+i+" "+e.missing);
            checks++;if(i<4&&!"unique_observed_NoteEditor_context_required".equals(e.missing))throw new AssertionError("wrong original refusal");
            checks++;if(e.persistentBytesVerified)throw new AssertionError("not persistent proof");
            names.add(i<4?"old_v67_rejects_actual_nonscroll_frame_"+(i+1):"old_v67_accepts_actual_v66_scrollable_frame");
        }
        StringBuilder out=new StringBuilder("{\"schema\":\"hepta.notes-nonscroll-previous-replay.v1\",\"all_pass\":true,\"cases\":5,\"assertions\":").append(checks).append(",\"case_names\":[");
        for(int i=0;i<names.size();i++){if(i>0)out.append(',');out.append('"').append(names.get(i)).append('"');}
        System.out.println(out.append("],\"historical_refusal_reproduced\":true,\"current_product_pass_adopted\":false}"));
    }
}
