"""Proof-only complete v13 EOF successor inverse. Never emits compiler input."""
import hashlib
OLD_SHA='aad22b14be14a33f0e12823f06b8ac780a023653eba7caebc4945ea281218100'
NEW_SHA='ea0a36c397900c03425fc125a4c94bbc1ee6166e23a65e8338feab4754c679ff'
OLD_BYTES=246507
NEW_BYTES=246671
PAIRS=[('            if(cancelledAfterActions)requireCancelledBrokerReceipt(cleanup.getJSONObject("broker_output"),broker);\n', '            if(cancelledAfterActions)requireCancelledBrokerReceipt(cleanup.getJSONObject("broker_output"),broker);\n            else if(workflowAbortedAfterBack)requireWorkflowRetirementBrokerReceipt(cleanup.getJSONObject("broker_output"),broker);\n'), ('            no(broker,"eof_seen");yes(broker,"persisted");\n', '            no(cleanup.getJSONObject("broker_output"),"eof_seen");yes(broker,"persisted");\n')]
def request_predecessor(raw):
 if type(raw) is not bytes:raise RuntimeError("complete Request bytes required")
 if len(raw)==OLD_BYTES and hashlib.sha256(raw).hexdigest()==OLD_SHA:return raw
 if len(raw)!=NEW_BYTES or hashlib.sha256(raw).hexdigest()!=NEW_SHA:raise RuntimeError("unreviewed complete EOF successor Request")
 proof=raw
 for old,new in reversed(PAIRS):
  a=old.encode("utf-8");b=new.encode("utf-8")
  if proof.count(b)!=1:raise RuntimeError("EOF inverse fragment is not unique")
  proof=proof.replace(b,a,1)
 if len(proof)!=OLD_BYTES or hashlib.sha256(proof).hexdigest()!=OLD_SHA:raise RuntimeError("complete pre-EOF Request not recovered")
 return proof
