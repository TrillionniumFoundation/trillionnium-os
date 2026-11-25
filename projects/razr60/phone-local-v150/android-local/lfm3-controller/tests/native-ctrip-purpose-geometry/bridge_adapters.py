"""Explicit Ctrip managed-profile IO for actual unmodified Service methods."""
def adapt(text, fragment, product):
    text = product.adapt(text, fragment)
    text = product.replace(text, '10,10,1010485,SystemClock.now-1,SystemClock.now+3000);',
                           '10,10,1010367,SystemClock.now-1,SystemClock.now+3000);')
    text = product.replace(text, 'final ProfileTarget productProfile;final WindowOwnership productWindow;Graph productCapturedGraph;',
                           'final ProfileTarget productProfile;final WindowOwnership productWindow;Graph productCapturedGraph;Map<String,Object> productCaptureMetadata;')
    text = product.replace(text, 'current.profileWindow=frame.profileWindow;current.capture=frame.capture;',
                           'current.captureEvidenceRaw=productCaptureMetadata==null?null:new JSONObject(productCaptureMetadata).toString();current.profileWindow=frame.profileWindow;current.capture=frame.capture;')
    return text
