package org.json;
/** JSONObject uses FixtureJson's strict whole-input parser, including its trailing-content rejection. */
public final class JSONTokener {private final String raw;public JSONTokener(String raw){this.raw=raw;}public Object nextValue()throws JSONException{return new JSONObject(raw);}public char nextClean(){return 0;}}
