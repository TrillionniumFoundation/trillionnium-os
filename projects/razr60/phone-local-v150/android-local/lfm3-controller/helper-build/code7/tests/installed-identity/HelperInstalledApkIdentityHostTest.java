import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Exact production Stamp and fileSha projection. Actual Android stat rows are
 * replayed as values; Android syscall transport is explicitly doubled. Hashing
 * reads real host fixture bytes, not an APK or an Android filesystem.
 */
public final class HelperInstalledApkIdentityHostTest {
    private static int checks;
    private static final List<String> cases=new ArrayList<String>();
    private interface Work {void run()throws Exception;}
    private static void check(boolean yes,String why){checks++;if(!yes)throw new AssertionError(why);}
    private static void test(String name,Work work)throws Exception{
        try{work.run();cases.add(name);}finally{Os.finish();}
    }
    private static void refused(Work work)throws Exception{
        boolean rejected=false;
        try{work.run();}catch(IllegalArgumentException|IllegalStateException|IOException expected){rejected=true;}
        check(rejected,"exact production code must refuse the dangerous state");
    }
    private static final class Jsons {
        static void need(boolean yes,String reason){if(!yes)throw new IllegalStateException(reason);}
    }
    private static final class OsConstants {
        static final int O_RDONLY=0,O_CLOEXEC=0x80000,O_NOFOLLOW=0x20000;
        static boolean S_ISREG(int mode){return (mode&0170000)==0100000;}
    }
    private static final class StructStat {
        final long st_dev,st_ino,st_size,st_mtime,st_ctime,st_nlink;
        final int st_mode,st_uid,st_gid;
        StructStat(long dev,long ino,long size,long mtime,long ctime,int mode,int uid,int gid,long links){
            st_dev=dev;st_ino=ino;st_size=size;st_mtime=mtime;st_ctime=ctime;
            st_mode=mode;st_uid=uid;st_gid=gid;st_nlink=links;
        }
        StructStat changed(String key,long value){
            return new StructStat("dev".equals(key)?value:st_dev,"ino".equals(key)?value:st_ino,
                    "size".equals(key)?value:st_size,"mtime".equals(key)?value:st_mtime,
                    "ctime".equals(key)?value:st_ctime,"mode".equals(key)?(int)value:st_mode,
                    "uid".equals(key)?(int)value:st_uid,"gid".equals(key)?(int)value:st_gid,
                    "links".equals(key)?value:st_nlink);
        }
    }
    private static final class Row {
        final String path;final StructStat stat;
        Row(String raw){
            Map<String,String> fields=new HashMap<String,String>();
            for(String part:raw.split("\\|",-1)){
                int at=part.indexOf('=');check(at>0,"actual stat key/value shape");
                check(fields.put(part.substring(0,at),part.substring(at+1))==null,"no duplicate actual stat field");
            }
            check(fields.size()==10,"exact actual stat field count");
            path=fields.get("path");check(path!=null&&path.endsWith("/base.apk"),"actual PM base path");
            stat=new StructStat(Long.parseLong(fields.get("dev")),Long.parseLong(fields.get("ino")),
                    Long.parseLong(fields.get("size")),Long.parseLong(fields.get("mtime")),Long.parseLong(fields.get("ctime")),
                    Integer.parseInt(fields.get("mode_hex"),16),Integer.parseInt(fields.get("uid")),
                    Integer.parseInt(fields.get("gid")),Long.parseLong(fields.get("nlink")));
        }
    }
    /** Deterministic syscall boundary, not a claim that host stat equals Android stat. */
    private static final class Os {
        static String logical;static Path fixture,ioRoot;static FileInputStream owner;static FileDescriptor descriptor;
        static StructStat initial,fdBefore,fdAfter,pathAfter;static int lstats,fstats,opens,sequence;
        static boolean breakAfterFirstFstat;
        static void snapshot(Row row,StructStat value)throws Exception{
            finish();logical=row.path;initial=value;fdBefore=value;fdAfter=value;pathAfter=value;
            lstats=0;fstats=0;opens=0;breakAfterFirstFstat=false;fixture=null;
        }
        static void content(Row row,StructStat value,byte[] payload)throws Exception{
            snapshot(row,value);
            fixture=ioRoot.resolve("content-"+(++sequence)+".bin");
            Files.write(fixture,payload,StandardOpenOption.CREATE_NEW);
        }
        static StructStat lstat(String path){
            if(!path.equals(logical))throw new AssertionError("unexpected path lookup");
            return lstats++==0?initial:pathAfter;
        }
        static FileDescriptor open(String path,int flags,int mode)throws Exception{
            check(path.equals(logical)&&fixture!=null,"only the owned fixture can be opened");
            check(flags==(OsConstants.O_RDONLY|OsConstants.O_CLOEXEC|OsConstants.O_NOFOLLOW)&&mode==0,
                    "actual unchanged no-follow read-only FD open flags");
            check(opens++==0,"no internal retry");
            owner=new FileInputStream(fixture.toFile());descriptor=owner.getFD();return descriptor;
        }
        static StructStat fstat(FileDescriptor fd)throws Exception{
            if(fd!=descriptor)throw new AssertionError("different file descriptor");
            check(fstats<2,"fixed before/after FD bracket");
            StructStat result=fstats++==0?fdBefore:fdAfter;
            if(breakAfterFirstFstat&&fstats==1)owner.close();
            return result;
        }
        static void finish()throws IOException{
            if(owner!=null){try{owner.close();}finally{owner=null;descriptor=null;}}
        }
    }

    private static String fileSha(String path,Stamp expected)throws Exception{
        FileDescriptor fd=Os.open(path,OsConstants.O_RDONLY|OsConstants.O_CLOEXEC|OsConstants.O_NOFOLLOW,0);
        try(FileInputStream in=new FileInputStream(fd)){
            Jsons.need(expected.same(new Stamp(Os.fstat(fd))),"opened APK differs");MessageDigest digest=MessageDigest.getInstance("SHA-256");
            byte[] buffer=new byte[65536];long bytes=0;int n;while((n=in.read(buffer))!=-1){bytes+=n;Jsons.need(bytes<=expected.size,"APK grew");digest.update(buffer,0,n);}
            Jsons.need(bytes==expected.size&&expected.same(new Stamp(Os.fstat(fd)))&&expected.same(Stamp.read(path)),"APK changed while hashing");
            byte[] sha=digest.digest();StringBuilder hex=new StringBuilder(64);for(byte b:sha)hex.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return hex.toString();
        }
    }
    private static final class Stamp {
        final long dev,ino,size,mtime,ctime;final int mode,ownerUid,ownerGid;final long links;
        Stamp(StructStat s){dev=s.st_dev;ino=s.st_ino;size=s.st_size;mtime=s.st_mtime;ctime=s.st_ctime;mode=s.st_mode;ownerUid=s.st_uid;ownerGid=s.st_gid;links=s.st_nlink;}
        static Stamp read(String path)throws Exception{Stamp s=new Stamp(Os.lstat(path));Jsons.need(OsConstants.S_ISREG(s.mode)&&s.size>0&&s.links>0&&(s.mode&0022)==0,"regular immutable APK required");return s;}
        boolean same(Stamp s){return dev==s.dev&&ino==s.ino&&size==s.size&&mtime==s.mtime&&ctime==s.ctime&&mode==s.mode&&ownerUid==s.ownerUid&&ownerGid==s.ownerGid&&links==s.links;}
    }

    private static String quote(String value){
        return "\""+value.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n")+"\"";
    }
    public static void main(String[] argv)throws Exception{
        check(argv.length==3,"actual stat text, new IO directory, new report");
        byte[] statBytes=Files.readAllBytes(Paths.get(argv[0]));
        String[] lines=new String(statBytes,StandardCharsets.UTF_8).split("\n");
        check(lines.length==2,"the two original actual APK rows");
        Row main=new Row(lines[0]),helper=new Row(lines[1]);
        check(main.stat.st_mode==0x816d&&main.stat.st_nlink==3&&main.stat.st_uid==1000
                &&main.stat.st_gid==1000&&main.stat.st_size==20985685,"original current main54 three-link values");
        check(helper.stat.st_mode==0x81a4&&helper.stat.st_nlink==1&&helper.stat.st_uid==1000
                &&helper.stat.st_gid==1000&&helper.stat.st_size==1381371,"original current helper5 values");
        Os.ioRoot=Paths.get(argv[1]);Files.createDirectory(Os.ioRoot);
        test("actual_main_three_link_read_only_stamp_is_admitted",()->{
            Os.snapshot(main,main.stat);Stamp s=Stamp.read(main.path);
            check(s.links==3&&s.mode==0x816d&&s.ownerUid==1000&&s.ownerGid==1000,"all actual stat identity fields retained");
            check(s.same(new Stamp(main.stat)),"same actual installed inode");
        });
        test("actual_helper_single_link_protected_stamp_is_admitted",()->{
            Os.snapshot(helper,helper.stat);check(Stamp.read(helper.path).same(new Stamp(helper.stat)),"actual helper remains admitted");
        });
        test("symlink_directory_and_fifo_are_rejected",()->{
            for(int mode:new int[]{0120777,0040555,0010444}){
                Os.snapshot(main,main.stat.changed("mode",mode));refused(()->Stamp.read(main.path));
            }
        });
        test("group_or_other_write_permission_is_rejected",()->{
            for(int extra:new int[]{0020,0002,0022}){
                Os.snapshot(main,main.stat.changed("mode",main.stat.st_mode|extra));refused(()->Stamp.read(main.path));
            }
        });
        test("empty_or_unlinked_metadata_is_rejected",()->{
            for(long n:new long[]{0,-1}){
                Os.snapshot(main,main.stat.changed("links",n));refused(()->Stamp.read(main.path));
                Os.snapshot(main,main.stat.changed("size",n));refused(()->Stamp.read(main.path));
            }
        });
        test("every_identity_field_including_link_owner_group_is_stable",()->{
            Stamp original=new Stamp(main.stat);
            String[] keys={"dev","ino","size","mtime","ctime","mode","uid","gid","links"};
            long[] changed={main.stat.st_dev+1,main.stat.st_ino+1,main.stat.st_size+1,main.stat.st_mtime+1,
                    main.stat.st_ctime+1,0100444,main.stat.st_uid+1,main.stat.st_gid+1,2};
            for(int i=0;i<keys.length;i++)check(!original.same(new Stamp(main.stat.changed(keys[i],changed[i]))),"changed "+keys[i]);
        });
        final byte[] payload="synthetic installed-file bytes\n".getBytes(StandardCharsets.UTF_8);
        final StructStat hashStat=main.stat.changed("size",payload.length);
        test("unchanged_file_sha_reads_one_fd_and_hashes_real_fixture_bytes",()->{
            Os.content(main,hashStat,payload);Stamp expected=Stamp.read(main.path);
            String actual=fileSha(main.path,expected);
            check(actual.equals("5da3e17090b46caacf7368c7797084fa3d1dc7b327b529cb537412457200f79e"),"unchanged real SHA256 over synthetic host bytes");
            check(Os.opens==1&&Os.fstats==2&&Os.lstats==2,"one open and both FD/path checks");
        });
        test("opened_fd_identity_mismatch_is_rejected_without_retry",()->{
            for(String key:new String[]{"ino","uid","gid","links"}){
                Os.content(main,hashStat,payload);Stamp expected=Stamp.read(main.path);
                Os.fdBefore=hashStat.changed(key,"links".equals(key)?2:99999);
                refused(()->fileSha(main.path,expected));
                check(Os.opens==1&&Os.fstats==1&&Os.lstats==1,"mismatched FD never reaches post-hash state");
            }
        });
        test("post_read_fd_or_path_replacement_and_link_changes_are_rejected",()->{
            for(boolean fdChange:new boolean[]{true,false}){
                for(String key:new String[]{"ino","uid","gid","links","mode","mtime","ctime"}){
                    Os.content(main,hashStat,payload);Stamp expected=Stamp.read(main.path);
                    StructStat changed=hashStat.changed(key,"links".equals(key)?2:"mode".equals(key)?0100666:99999);
                    if(fdChange)Os.fdAfter=changed;else Os.pathAfter=changed;
                    refused(()->fileSha(main.path,expected));check(Os.opens==1,"no retry after mutation");
                }
            }
        });
        test("short_grown_or_failed_read_never_returns_a_hash",()->{
            for(long length:new long[]{payload.length-1,payload.length+1}){
                Os.content(main,hashStat.changed("size",length),payload);Stamp expected=Stamp.read(main.path);
                refused(()->fileSha(main.path,expected));check(Os.opens==1,"read-size refusal does not reopen");
            }
            Os.content(main,hashStat,payload);Stamp expected=Stamp.read(main.path);Os.breakAfterFirstFstat=true;
            refused(()->fileSha(main.path,expected));check(Os.opens==1,"I/O failure does not reopen");
        });
        check(cases.size()==10,"only the ten focused case groups");
        StringBuilder names=new StringBuilder("[");
        for(String name:cases){if(names.length()>1)names.append(',');names.append(quote(name));}names.append(']');
        String json="{\"schema\":\"hepta.helper-installed-apk-identity-host-checks.v1\",\"all_pass\":true,\"cases\":"+cases.size()
                +",\"assertions\":"+checks+",\"case_names\":"+names
                +",\"actual_stat_values_replayed\":true,\"android_syscalls_doubled\":true,\"host_hash_payload_synthetic\":true"
                +",\"actual_android_file_access_executed\":false,\"package_manager_or_certificate_executed\":false"
                +",\"actual_three_link_apk_rehashed_here\":false,\"phone_actions\":0,\"business_verified\":false}\n";
        Files.write(Paths.get(argv[2]),json.getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println("HelperInstalledApkIdentityHostTest cases="+cases.size()+" assertions="+checks);
    }
}
