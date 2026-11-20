"""Optional adapter of generated source; does not edit a frozen source tree."""


def adapt(source):
    if '"prompt-evidence.inc"' in source or 'hepta_capture_prompt_evidence(&o' in source:
        raise ValueError("prompt evidence adapter already applied")
    def once(old, new):
        nonlocal source
        if source.count(old) != 1:
            raise ValueError("prompt evidence integration location differs: " + old)
        source = source.replace(old, new)
    once('#include "model-runtime.inc"',
         '#include "model-runtime.inc"\n#include "prompt-evidence.inc"')
    once('    hepta_release_vocabulary();\n    if(!hepta_model_is_unchanged(o.model))',
         '    if(!hepta_capture_prompt_evidence(&o,inputs,prompt,prompt_size,formatted_sha)){\n'
         '        error="private_prompt_evidence_failed";goto sdk_cleanup;\n'
         '    }\n'
         '    hepta_release_vocabulary();\n    if(!hepta_model_is_unchanged(o.model))')
    once('    hepta_write_prompt_budget(f);',
         '    hepta_write_prompt_budget(f);\n    hepta_write_prompt_evidence_meta(f);')
    return source
