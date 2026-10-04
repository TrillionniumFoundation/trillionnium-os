#!/usr/bin/env python3
"""Source-selector regressions, including a licensed real Make macro fixture."""
import hashlib,importlib.util,json,os,shutil,subprocess,tempfile,unittest
from unittest.mock import patch
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('sdk_selection',ROOT/'tools/verify-owner-open-sdk-selection.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
FIXTURE=Path(__file__).parent/'fixtures/android_soong_config_bool'

class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        for rel in [v.BP,v.OWNER_XML,v.PRODUCT]:
            p=self.root/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/rel,p)
        self.bp=self.root/v.BP;self.res=self.root/v.OWNER_XML;self.prod=self.root/v.PRODUCT
    def tearDown(self):self.temp.cleanup()
    def change(self,path,before,after):
        text=path.read_text();self.assertIn(before,text);path.write_text(text.replace(before,after,1))
    def rejected(self):self.assertFalse(v.verify(self.root)['ok'])
    def test_owner_and_sealed_source_contract(self):
        r=v.verify(self.root);self.assertTrue(r['ok'],r['errors']);self.assertEqual(len(r['facts']['owner_platform_services']),7);self.assertFalse(r['facts']['actual_soong_compiled'])
    def test_agent_api_exclusion_must_match_role(self):
        self.change(self.bp,'internal/AgentSystemApi*.java','internal/UnusedAgentSystemApi*.java');self.rejected()
    def test_lease_exclusion_must_match_role(self):
        self.change(self.bp,'internal/CapabilityLease*.java','internal/UnusedCapabilityLease*.java');self.rejected()
    def test_plugin_interface_exclusion_must_match_role(self):
        self.change(self.bp,'internal/plugin/*.java','internal/unused-plugin/*.java');self.rejected()
    def test_typed_uri_semantics_exclusion_must_match_role(self):
        self.change(self.bp,'internal/OpenUriLeaseSemanticsV1*.java','internal/UnusedOpenUriLeaseSemanticsV1*.java');self.rejected()
    def test_ordinary_service_must_remain(self):
        self.change(self.res,'        <item>org.trillionnium.platform.internal.ProfileManagerService</item>\n','');self.rejected()
    def test_old_api_boot_service_cannot_be_restored(self):
        self.change(self.res,'    </string-array>','        <item>org.trillionnium.platform.internal.AgentSystemApiService</item>\n    </string-array>');self.rejected()
    def test_old_lease_boot_service_cannot_be_restored(self):
        self.change(self.res,'    </string-array>','        <item>org.trillionnium.platform.internal.CapabilityLeaseBrokerService</item>\n    </string-array>');self.rejected()
    def test_resource_overlay_order_is_required(self):
        self.change(self.bp,'["trillionnium/res/res", "owner-open/res"]','["owner-open/res", "trillionnium/res/res"]');self.rejected()
    def test_sealed_identity_dependency_must_remain(self):
        self.change(self.bp,'                    "trillionnium-agent-identity-product",\n','');self.rejected()
    def test_owner_unconditional_feature_edge_is_rejected(self):
        self.change(self.bp,'    installable: true,','    installable: true,\n    required: ["org.trillionnium.agent.system_api.xml"],');self.rejected()
    def test_owner_static_dependency_is_rejected(self):
        self.change(self.bp,'    installable: true,','    installable: true,\n    static_libs: ["trillionnium-agent-identity-product"],');self.rejected()
    def test_ordinary_sdk_default_input_cannot_be_dropped(self):
        self.change(self.bp,'        ":trillionnium-sdk-internal-sources",\n','');self.rejected()
    def test_ordinary_sdk_hal_dependency_cannot_be_dropped(self):
        self.change(self.bp,'        "vendor.trillionnium.health-V2-java",\n','');self.rejected()
    def test_owner_bool_export_must_be_active(self):
        self.change(self.prod,'$(call soong_config_set_bool,trillionnium_owner_open,enabled,true)','# disabled owner selector');self.rejected()
    def test_selector_namespace_must_match_export(self):
        self.change(self.bp,'config_namespace: "trillionnium_owner_open"','config_namespace: "unrelated_owner_open"');self.rejected()
    def test_selector_module_parent_must_support_properties(self):
        self.change(self.bp,'module_type: "android_app"','module_type: "java_library"');self.rejected()
    def test_additional_resource_override_is_rejected(self):
        self.change(self.res,'</resources>','    <string name="config_externalSystemServer">different.Server</string>\n</resources>');self.rejected()
    def test_duplicate_module_is_rejected(self):
        self.bp.write_text(self.bp.read_text()+'\njava_library { name: "org.trillionnium.platform", }\n');self.rejected()
    def test_blueprint_integer_cannot_match_bool(self):
        self.change(self.bp,'use_resource_processor: false','use_resource_processor: 0');self.rejected()
    def test_blueprint_bool_arithmetic_is_rejected(self):
        self.change(self.bp,'use_resource_processor: false','use_resource_processor: false + false');self.rejected()
    def test_blueprint_non_map_module_body_is_rejected(self):
        self.bp.write_text(self.bp.read_text()+'\nfilegroup [1]\n');self.rejected()
    def test_real_source_is_required(self):
        self.res.unlink();self.res.symlink_to(ROOT/v.OWNER_XML);self.rejected()
    def test_entry_swap_between_stat_and_open_is_rejected(self):
        outside=self.root/'outside.bp';outside.write_bytes(self.bp.read_bytes())
        real_open=os.open;swapped=False
        def swapping_open(path,flags,*args,**kwargs):
            nonlocal swapped
            if path=='Android.bp' and not swapped:
                swapped=True;self.bp.unlink();self.bp.symlink_to(outside)
            return real_open(path,flags,*args,**kwargs)
        with patch.object(v.os,'open',side_effect=swapping_open):self.rejected()
        self.assertTrue(swapped)
    def test_file_growth_has_actual_bounded_descriptor_read(self):
        real_open=os.open;real_read=os.read;tracked=set();grew=False;actual_read=0
        def tracking_open(path,flags,*args,**kwargs):
            fd=real_open(path,flags,*args,**kwargs)
            if path=='Android.bp':tracked.add(fd)
            return fd
        def growing_read(fd,size):
            nonlocal grew,actual_read
            if fd in tracked and not grew:
                grew=True
                with self.bp.open('ab') as output:output.write(b' '*(v.MAX_BYTES+1))
            data=real_read(fd,size)
            if fd in tracked:actual_read+=len(data)
            return data
        with patch.object(v.os,'open',side_effect=tracking_open),patch.object(v.os,'read',side_effect=growing_read):self.rejected()
        self.assertTrue(grew);self.assertLessEqual(actual_read,v.MAX_BYTES+1)
    def bool_mutants(self):
        original=self.prod.read_text();setter=v.OWNER_BOOL
        return {
            'trailing_bool_false':original+'\n$(call soong_config_set_bool,trillionnium_owner_open,enabled,false)\n',
            'trailing_generic_empty_set':original+'\n$(call soong_config_set,trillionnium_owner_open,enabled,)\n',
            'trailing_direct_empty_assignment':original+'\nSOONG_CONFIG_trillionnium_owner_open_enabled :=\n',
            'true_inside_disabled_conditional':original.replace(setter,'ifeq (never,always)\n'+setter+'\nendif'),
            'true_inside_unused_define':original.replace(setter,'define unused_owner_selector\n'+setter+'\nendef'),
            'trailing_namespace_variable_list_reset':original+'\nSOONG_CONFIG_trillionnium_owner_open :=\n',
            'trailing_namespace_registry_reset':original+'\nSOONG_CONFIG_NAMESPACES :=\n',
        }
    def test_seven_observed_make_false_passes_are_rejected(self):
        mutants=self.bool_mutants()
        for case,text in mutants.items():
            with self.subTest(case=case):self.prod.write_text(text);self.rejected()
    def test_owner_bool_inside_authorized_adb_condition_is_rejected(self):
        self.change(self.prod,v.OWNER_BOOL,v.OWNER_MAKE_CONDITIONS[0]+'\n'+v.OWNER_BOOL+'\nendif');self.rejected()
    def test_unknown_condition_is_rejected(self):
        self.prod.write_text(self.prod.read_text()+'\nifeq (true,true)\nendif\n');self.rejected()
    def test_dynamic_eval_is_rejected(self):
        self.prod.write_text(self.prod.read_text()+'\n$(eval SOONG_CONFIG_NAMESPACES :=)\n');self.rejected()
    def test_indirect_setter_call_is_rejected(self):
        self.prod.write_text(self.prod.read_text()+'\n$(call unrelated_setter,trillionnium_owner_open,enabled,false)\n');self.rejected()
    def test_indirect_value_in_allowed_assignment_is_rejected(self):
        self.prod.write_text(self.prod.read_text()+'\nPRODUCT_PACKAGES += $(call soong_config_set_bool,trillionnium_owner_open,enabled,false)\n');self.rejected()
    def test_unfinished_continuation_is_rejected(self):
        self.prod.write_text(self.prod.read_text()+'\nPRODUCT_PACKAGES += \\');self.rejected()
    def test_comment_escaped_newline_cannot_hide_bool(self):
        self.change(self.prod,v.OWNER_BOOL,'# hidden owner bool \\\n'+v.OWNER_BOOL);self.rejected()
    def test_assignment_comment_escaped_newline_cannot_hide_bool(self):
        self.change(self.prod,v.OWNER_BOOL,'PRODUCT_PACKAGES += ordinary # hidden owner bool \\\n'+v.OWNER_BOOL);self.rejected()
    def test_vertical_tab_does_not_create_make_line(self):
        self.change(self.prod,v.OWNER_BOOL,'# hidden owner bool\v'+v.OWNER_BOOL);self.rejected()
    def test_form_feed_does_not_create_make_line(self):
        self.change(self.prod,v.OWNER_BOOL,'# hidden owner bool\f'+v.OWNER_BOOL);self.rejected()
    def test_leading_recipe_tab_cannot_create_bool_statement(self):
        self.change(self.prod,v.OWNER_BOOL,'\t'+v.OWNER_BOOL);self.rejected()
    @unittest.skipUnless(shutil.which('make'),'GNU Make fixture needs make')
    def test_actual_make_assignment_tab_continuations_remain_supported(self):
        self.prod.write_text(self.prod.read_text().replace('\n    ','\n\t'))
        result=v.verify(self.root);self.assertTrue(result['ok'],result['errors'])
        self.assertEqual(self.actual_bool_values(self.prod),dict(namespaces='trillionnium_owner_open',variables='enabled',enabled='true',type='bool'))
    def actual_bool_values(self,product):
        mk=self.root/'actual-export.mk'
        mk.write_text('include '+str(FIXTURE/'helpers.mk')+'\ninclude '+str(product)+'\nall:\n\t@printf \'namespaces=%s\\nvariables=%s\\nenabled=%s\\ntype=%s\\n\' \'$(SOONG_CONFIG_NAMESPACES)\' \'$(SOONG_CONFIG_trillionnium_owner_open)\' \'$(SOONG_CONFIG_trillionnium_owner_open_enabled)\' \'$(SOONG_CONFIG_TYPE_trillionnium_owner_open_enabled)\'\n')
        r=subprocess.run(['make','--no-print-directory','-f',str(mk)],capture_output=True,text=True,timeout=10,env=dict(os.environ,LC_ALL='C'))
        self.assertEqual(r.returncode,0,r.stderr)
        return dict(line.split('=',1) for line in r.stdout.splitlines())
    @unittest.skipUnless(shutil.which('make'),'GNU Make fixture needs make')
    def test_licensed_make_baseline_and_seven_disabled_exports(self):
        mutants=self.bool_mutants()
        self.assertEqual(self.actual_bool_values(self.prod),dict(namespaces='trillionnium_owner_open',variables='enabled',enabled='true',type='bool'))
        for case,text in mutants.items():
            with self.subTest(case=case):
                self.prod.write_text(text);self.rejected();values=self.actual_bool_values(self.prod)
                self.assertNotEqual(values,dict(namespaces='trillionnium_owner_open',variables='enabled',enabled='true',type='bool'))
    def test_real_make_macro_exports_owner_bool(self):
        if shutil.which('make') is None:self.skipTest('GNU Make unavailable; full Android/Soong is still required')
        provenance=json.loads((FIXTURE/'provenance.json').read_text())
        macro=FIXTURE/'helpers.mk';license=FIXTURE/'LICENSE'
        self.assertEqual(hashlib.sha256(macro.read_bytes()).hexdigest(),provenance['fixture_sha256'])
        self.assertEqual(hashlib.sha256(license.read_bytes()).hexdigest(),provenance['license_sha256'])
        self.assertEqual(provenance['license'],'Apache-2.0')
        for case,action,enabled,kind in [
            ('unset','', '', ''),
            ('false','$(call soong_config_set_bool,trillionnium_owner_open,enabled,false)\n','','bool'),
            ('owner','include '+str(self.prod)+'\n','true','bool')]:
            with self.subTest(case=case):
                mk=self.root/(case+'.mk')
                mk.write_text('include '+str(macro)+'\n'+action+'all:\n\t@printf \'enabled=%s\\ntype=%s\\n\' \'$(SOONG_CONFIG_trillionnium_owner_open_enabled)\' \'$(SOONG_CONFIG_TYPE_trillionnium_owner_open_enabled)\'\n')
                r=subprocess.run(['make','--no-print-directory','-f',str(mk)],capture_output=True,text=True,timeout=10,env=dict(os.environ,LC_ALL='C'))
                self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,'enabled='+enabled+'\ntype='+kind+'\n')

if __name__=='__main__':unittest.main()
