package org.trillionnium.hepta.local;
public final class LocalModelEngine {final java.io.File file;final LocalRuntimeConfig config;public LocalModelEngine(java.io.File f,LocalRuntimeConfig c){file=f;config=c;}public boolean isBusy(){return false;}public java.io.File modelFile(){return file;}public LocalRuntimeConfig configuration(){return config;}public void cancelActive(){}}
