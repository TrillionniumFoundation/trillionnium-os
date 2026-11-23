package org.trillionnium.hepta.webhelper;
import java.io.File;
import android.os.ParcelFileDescriptor;
/** Record transport double; actual EvidenceFiles byte/hash/readonly-IO is not tested here. */
final class EvidenceFiles {
    static final class Record {
        final File path;final long length;final String sha;int opens;boolean failOpen;
        Record(File p,long n,String s){path=p;length=n;sha=s;}
        ParcelFileDescriptor openReadOnly()throws Exception{opens++;if(failOpen)throw new Exception("synthetic open failure");return new ParcelFileDescriptor();}
    }
}
