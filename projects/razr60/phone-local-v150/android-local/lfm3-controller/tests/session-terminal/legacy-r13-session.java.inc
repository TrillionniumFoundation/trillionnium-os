// Exact predecessor method bodies; only invocation names are changed by the host runner.
// c8a1f0f9d2b3de3d75758a661ca5efc85a582e4f LocalTaskSession.java SHA256 a18389449b2c737233004dfab8bcbd70d5e079752b6c414e0435967d82ac20f5
private byte[] snapshotSession(String status,boolean cleanupKnown)throws Exception {
        if(taskId!=null&&controller!=null&&taskId.equals(controller.currentTaskId()))actualScopeSha=controller.currentActualScopeSha256();
            JSONObject value=new JSONObject().put("schema","hepta.local-session.v1").put("status",status)
                .put("task_id",taskId==null?JSONObject.NULL:taskId).put("origin",origin==null?JSONObject.NULL:origin)
                .put("instruction_sha256",instructionSha==null?JSONObject.NULL:instructionSha)
                    .put("task_authorization_sha256",taskAuthorization==null?JSONObject.NULL:taskAuthorization.sha256)
                    .put("task_authorization",taskAuthorization==null?JSONObject.NULL:new JSONObject(taskAuthorization.evidence()))
                    .put("background_request",backgroundSelection==null?JSONObject.NULL:backgroundSelection.json())
                .put("debug_nonce_sha256",nonceSha==null?JSONObject.NULL:nonceSha)
                .put("expected_scope_sha256",QualificationScopeConfig.nullable(expectedScopeSha))
                .put("actual_scope_sha256",QualificationScopeConfig.nullable(actualScopeSha))
                .put("state",state).put("pending",pending).put("running",isRunning()).put("blocked",blocked)
                .put("cleanup_known",cleanupKnown).put("app_uid",android.os.Process.myUid()).put("updated_wall_ms",System.currentTimeMillis())
                .put("external_model",false).put("automatic_resume",false).put("goal_independently_verified",false);
            if(startupRecovery!=null)value.put("startup_recovery",startupRecovery);
            if(acknowledgedSession!=null){
                RecoveryJournalTransaction.Acknowledgement a=acknowledgedSession.acknowledgement;
                value.put("session_id",a.sessionId).put("recovery_transaction_id",a.transactionId)
                    .put("recovery_ack_sha256",a.ackSha256).put("old_native_cleanup","unknown")
                    .put("old_session_disposition","interrupted_not_resumed")
                    .put("process_inventory_scope",RecoveryJournalTransaction.SCOPE);
            }
            if(lastResult!=null)value.put("evidence_directory",lastResult.evidenceDirectory==null?JSONObject.NULL:lastResult.evidenceDirectory.getPath())
                .put("model_reported_success",lastResult.modelReportedSuccess).put("steps",lastResult.steps)
                .put("completion_verified",lastResult.completionVerified).put("completion_evidence",new JSONObject(lastResult.completionEvidence))
                .put("goal_independently_verified",lastResult.completionVerified);
            return value.toString(2).getBytes(StandardCharsets.UTF_8);
    }

private void writeSessionSnapshot(byte[] snapshot,LeaseState leases)throws Exception {
        String stage="decode_snapshot";
        AtomicFile destination=null;FileOutputStream out=null;
        try{
            // This private copy cannot acquire newer task/authorization fields after queueing.
            JSONObject value=parseSessionJson(snapshot);
            stage="capture_lease_fields";
            value.put("background_lease_unreleased",leases.background).put("web_helper_lease_unreleased",leases.web);
            if(journalQueue.failed())value.put("blocked",true).put("cleanup_known",false)
                    .put("session_journal_failure_observed",true);
            stage="atomic_destination";
            destination=new AtomicFile(new File(context.getFilesDir().getCanonicalFile(),"control-session.json"));
            stage="encode_snapshot";
            byte[] written=value.toString(2).getBytes(StandardCharsets.UTF_8);
            if(written.length>SESSION_LIMIT)throw new IOException("session record exceeds bounded size");
            stage="atomic_start_write";out=destination.startWrite();
            stage="private_file_mode";android.system.Os.fchmod(out.getFD(),0600);
            stage="write_flush_file_sync";out.write(written);out.flush();out.getFD().sync();
            // Android AtomicFile may log a sync/rename failure without throwing.
            // Explicit sync and byte/sidecar checks must precede the pending-start permission.
            stage="atomic_finish_write";destination.finishWrite(out);out=null;
            stage="committed_file_mode";
            File base=destination.getBaseFile();android.system.Os.chmod(base.getPath(),0600);
            stage="readback_and_sidecars";
            if(recordExists(new File(base.getPath()+".new"))||recordExists(new File(base.getPath()+".bak"))
                    ||!java.util.Arrays.equals(written,readSessionRecord(base)))
                throw new IOException("session commit readback or sidecar check failed");
            stage="canonical_parent";File parent=base.getParentFile().getCanonicalFile();
            stage="open_parent";
            FileDescriptor directory=android.system.Os.open(parent.getPath(),android.system.OsConstants.O_RDONLY
                    |android.system.OsConstants.O_NOFOLLOW|android.system.OsConstants.O_CLOEXEC,0);
            try{
                stage="verify_parent_identity";android.system.StructStat info=android.system.Os.fstat(directory);
                if(!android.system.OsConstants.S_ISDIR(info.st_mode)||info.st_uid!=android.os.Process.myUid())
                    throw new IOException("session commit parent identity differs");
                stage="parent_fsync_or_close";android.system.Os.fsync(directory);
            }finally{android.system.Os.close(directory);}
        }catch(Exception error){
            IOException observed=new IOException("session journal write failed at "+stage,error);
            logJournalFailure(journalFailureDetails(stage,observed));
            if(out!=null&&destination!=null)destination.failWrite(out);
            throw observed;
        }
    }
