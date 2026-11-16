"""Catch SDK C++ generation failures without changing vendor ABI or success gates."""
def adapt(source):
    def once(old,new):
        nonlocal source
        if source.count(old)!=1:
            raise ValueError("SDK exception integration location differs: "+old)
        source=source.replace(old,new)
    once('#include "warm-state.inc"', '#include "warm-state.inc"\n#include "sdk-exception-metadata.inc"')
    once('generate_rc=geniex_llm_generate(llm,&in,&lo);','generate_rc=hepta_guarded_llm_generate(llm,&in,&lo);')
    once('    if(generate_rc!=0&&!error)error="sdk_generate_failed";',
         '    if(hepta_sdk_generate_exception()->kind)error="sdk_cpp_exception";\n'
         '    else if(generate_rc!=0&&!error)error="sdk_generate_failed";')
    once('    const char *outcome=complete?"completed":cancel_signal?"signal_observed":deadline_hit?"deadline_observed":"not_completed";',
         '    const char *outcome=hepta_sdk_generate_exception()->kind?"sdk_exception":complete?"completed":cancel_signal?"signal_observed":deadline_hit?"deadline_observed":"not_completed";')
    once('    status=complete?0:cancel_signal?128+(int)cancel_signal:deadline_hit?124:70;',
         '    status=hepta_sdk_generate_exception()->kind?70:complete?0:cancel_signal?128+(int)cancel_signal:deadline_hit?124:70;')
    once('    if(!fence(PH_RESULT)){complete=false;outcome=cancel_signal?"signal_observed":"deadline_observed";status=cancel_signal?128+(int)cancel_signal:124;}',
         '    if(!fence(PH_RESULT)){complete=false;outcome=hepta_sdk_generate_exception()->kind?"sdk_exception":cancel_signal?"signal_observed":"deadline_observed";status=hepta_sdk_generate_exception()->kind?70:cancel_signal?128+(int)cancel_signal:124;}')
    once('    fputs(",\\"input_sha256\\":{",f);',
         '    fputc(\',\',f);hepta_write_sdk_exception(f);\n    fputs(",\\"input_sha256\\":{",f);')
    return source
