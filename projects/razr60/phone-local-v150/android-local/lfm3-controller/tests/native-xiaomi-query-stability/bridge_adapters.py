"""Explicit managed-profile Android IO ports for a separate actual-method host.
Production Service bodies and the actual Session/Domain classes stay verbatim.
The ports create no device ownership, real capture, model run or phone effect.
"""
def replace(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError("nonunique query fixture adapter: " + old[:120])
    return text.replace(old, new, 1)

def adapt(text, fragment):
    text = text.replace("NativeActionBridgeHost", "NativeProductQueryBridgeHost")
    text = replace(text, "    final class Fixture {\n", "    String productOwner=\"在小米商城查询AX3000T价格\";\n    final class Fixture {\n")
    text = replace(text,
        "        final File actualJournalDirectory;boolean failActualOutcome;",
        "        final File actualJournalDirectory;boolean failActualOutcome;\n        final ProfileTarget productProfile;final WindowOwnership productWindow;Graph productCapturedGraph;")
    text = replace(text,
        '            owner=NativeActionSnapshotCheck.SEARCH.equals(p)?"在小米商城查一下小米AX3000T的售价":NativeAppProviderHostTest.OWNER;\n'
        '            BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(owner,raw.pkg,Collections.singleton(raw.pkg));',
        '            owner=productOwner;productProfile=productProfile();\n'
        '            BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(owner,raw.pkg,Collections.singleton(raw.pkg),productProfile);')
    text = replace(text,
        '            NativeAppEvidence.Installed installed=new NativeAppEvidence.Installed(raw.pkg,NativeActionSnapshotCheck.SEARCH.equals(p)?10485:10367,\n'
        '                    NativeActionSnapshotCheck.SEARCH.equals(p)?20261010L:1779L,\n'
        '                    Collections.singletonMap("base",NativeActionSnapshotCheck.SEARCH.equals(p)?"95883c057eb15bc6e50a82f2e22da13b77980871624f60a2fb9e50cfdf4a8373":NativeCtripFlightPage.BASE_APK_SHA256));',
        '            productWindow=new WindowOwnership(productProfile,background.generation,7,96,1000123,456,\n'
        '                    "22222222-2222-4222-8222-222222222222","11111111-1111-4111-8111-111111111111",\n'
        '                    10,10,1010485,SystemClock.now-1,SystemClock.now+3000);\n'
        '            NativeAppEvidence.Installed installed=new NativeAppEvidence.Installed(productProfile);')
    text = replace(text,
        '            if(selection==null||selection.profileTarget!=null||selection.independentProfileDisplay||selection.independentPersonalDisplay)\n'
        '                throw new AssertionError("legacy action fixture cannot confirm a profile or independent display scope");',
        '            if(selection==null||fixtureOwner.fixture==null||selection.profileTarget==null\n'
        '                    ||!selection.profileTarget.same(fixtureOwner.fixture.productProfile)||selection.independentPersonalDisplay)\n'
        '                throw new AssertionError("explicit product host profile port binding differs");')
    text = replace(text,
        '            throw new AssertionError("legacy action fixture has no historical profile RPC proof");',
        '            requireLegacyOnly();proof.requireMatches(selection.profileTarget,generation,display,window,task,captured);')
    text = replace(text,
        '        if(selected!=background||selected.selection.profileTarget!=null||selected.selection.independentProfileDisplay\n'
        '                ||selected.selection.independentPersonalDisplay)throw new AssertionError("fixture cannot select an actual owned/profile root");',
        '        if(selected!=background||!selected.selection.profileTarget.same(fixture.productProfile))\n'
        '            throw new AssertionError("explicit product host root port binding differs");')
    text = replace(text,
        '        if(selected.selection.profileTarget!=null)throw new AssertionError("fixture has no actual profile RPC authority");',
        '        if(selected!=background||frame.profileWindow==null||window.getDisplayId()!=7||window.getId()!=96)\n'
        '            throw new AssertionError("explicit product host task port binding differs");\n'
        '        frame.profileWindow.requireMatches(fixture.productProfile,background.generation,7,96,1000123,SystemClock.now);')
    text = replace(text,
        '        throw new AssertionError("legacy action fixture cannot produce an actual profile proof");',
        '        checkReadBudget(budget);\n'
        '        if(selected!=background||root.data!=fixture.data.get("0"))throw new AssertionError("explicit product host profile RPC root differs");\n'
        '        return fixture.productWindow;')
    text = replace(text,
        '    static ObservedScrollActions readScrollActions(AccessibilityNodeInfo n){return n.data.scrollOverride!=null?n.data.scrollOverride:ObservedScrollActions.observed(n.isScrollable()?Arrays.asList("up","down"):Collections.<String>emptyList());}',
        '    static ObservedScrollActions readScrollActions(AccessibilityNodeInfo n){\n'
        '        if(n.data.scrollOverride!=null)return n.data.scrollOverride;\n'
        '        String raw=n.s("scroll_actions");List<String> directions=new ArrayList<String>();\n'
        '        String[] parts=raw.split("\\\\|");for(int i=2;i<parts.length;i++)directions.add(parts[i]);\n'
        '        return ObservedScrollActions.observed(directions);\n'
        '    }')
    text = replace(text,
        '            beginNativeActionCensus(g,background,budget);',
        '            g.profileWindow=productWindow;beginNativeActionCensus(g,background,budget);')
    text = replace(text,
        '            return new NativeAppEvidence.Frame(task,selection.taskTarget.ownerSha256,selection.taskTarget.targetSha256,authorization.sha256,NativeAppObservation.selectionSha(selection),obs,raw.pkg,background.generation,\n'
        '                    tree,hash("host-state:"+tree),hash("host-screen:"+obs),hash("host-record:"+obs),hash("host-completion:"+obs),\n'
        '                    7,96,0,1224,2992,0,0,1224,2992,SystemClock.now,false,true,nodes,1,true);',
        '            return productFrame(this,nodes,tree,obs);')
    text = replace(text,
        'SystemClock.now+=10;Graph g=graph(values,null);frame=frame(retained(g),g.digest);',
        'SystemClock.now+=10;Graph g=graph(values,null);productCapturedGraph=g;frame=frame(retained(g),g.digest);')
    text = replace(text,
        '            current.capture=frame.capture;current.screenshotSha256=frame.screenshotSha;',
        '            current.profileWindow=frame.profileWindow;current.capture=frame.capture;current.screenshotSha256=frame.screenshotSha;')
    text = replace(text,
        '                        if(actualJournalDirectory!=null){',
        '                        if(failActualOutcome&&leaf.startsWith("native-app-outcome-"))throw new java.io.IOException("explicit host outcome journal failure");\n'
        '                        if(actualJournalDirectory!=null){')
    # No production method is altered. The generated wrapper's additional main
    # executes only the newly named product cases, never claims the old matrix.
    if not text.rstrip().endswith("}"):
        raise RuntimeError("complete bridge class required")
    return text.rstrip()[:-1] + "\n" + fragment + "\n}\n"
