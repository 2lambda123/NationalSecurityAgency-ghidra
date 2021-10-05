/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
package SWIG;


/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */


public class SBBreakpoint {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBBreakpoint(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBBreakpoint obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  @SuppressWarnings("deprecation")
  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        lldbJNI.delete_SBBreakpoint(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public SBBreakpoint() {
    this(lldbJNI.new_SBBreakpoint__SWIG_0(), true);
  }

  public SBBreakpoint(SBBreakpoint rhs) {
    this(lldbJNI.new_SBBreakpoint__SWIG_1(SBBreakpoint.getCPtr(rhs), rhs), true);
  }

  public int GetID() {
    return lldbJNI.SBBreakpoint_GetID(swigCPtr, this);
  }

  public boolean IsValid() {
    return lldbJNI.SBBreakpoint_IsValid(swigCPtr, this);
  }

  public void ClearAllBreakpointSites() {
    lldbJNI.SBBreakpoint_ClearAllBreakpointSites(swigCPtr, this);
  }

  public SBTarget GetTarget() {
    return new SBTarget(lldbJNI.SBBreakpoint_GetTarget(swigCPtr, this), true);
  }

  public SBBreakpointLocation FindLocationByAddress(java.math.BigInteger vm_addr) {
    return new SBBreakpointLocation(lldbJNI.SBBreakpoint_FindLocationByAddress(swigCPtr, this, vm_addr), true);
  }

  public int FindLocationIDByAddress(java.math.BigInteger vm_addr) {
    return lldbJNI.SBBreakpoint_FindLocationIDByAddress(swigCPtr, this, vm_addr);
  }

  public SBBreakpointLocation FindLocationByID(int bp_loc_id) {
    return new SBBreakpointLocation(lldbJNI.SBBreakpoint_FindLocationByID(swigCPtr, this, bp_loc_id), true);
  }

  public SBBreakpointLocation GetLocationAtIndex(long index) {
    return new SBBreakpointLocation(lldbJNI.SBBreakpoint_GetLocationAtIndex(swigCPtr, this, index), true);
  }

  public void SetEnabled(boolean enable) {
    lldbJNI.SBBreakpoint_SetEnabled(swigCPtr, this, enable);
  }

  public boolean IsEnabled() {
    return lldbJNI.SBBreakpoint_IsEnabled(swigCPtr, this);
  }

  public void SetOneShot(boolean one_shot) {
    lldbJNI.SBBreakpoint_SetOneShot(swigCPtr, this, one_shot);
  }

  public boolean IsOneShot() {
    return lldbJNI.SBBreakpoint_IsOneShot(swigCPtr, this);
  }

  public boolean IsInternal() {
    return lldbJNI.SBBreakpoint_IsInternal(swigCPtr, this);
  }

  public long GetHitCount() {
    return lldbJNI.SBBreakpoint_GetHitCount(swigCPtr, this);
  }

  public void SetIgnoreCount(long count) {
    lldbJNI.SBBreakpoint_SetIgnoreCount(swigCPtr, this, count);
  }

  public long GetIgnoreCount() {
    return lldbJNI.SBBreakpoint_GetIgnoreCount(swigCPtr, this);
  }

  public void SetCondition(String condition) {
    lldbJNI.SBBreakpoint_SetCondition(swigCPtr, this, condition);
  }

  public String GetCondition() {
    return lldbJNI.SBBreakpoint_GetCondition(swigCPtr, this);
  }

  public void SetAutoContinue(boolean auto_continue) {
    lldbJNI.SBBreakpoint_SetAutoContinue(swigCPtr, this, auto_continue);
  }

  public boolean GetAutoContinue() {
    return lldbJNI.SBBreakpoint_GetAutoContinue(swigCPtr, this);
  }

  public void SetThreadID(java.math.BigInteger sb_thread_id) {
    lldbJNI.SBBreakpoint_SetThreadID(swigCPtr, this, sb_thread_id);
  }

  public java.math.BigInteger GetThreadID() {
    return lldbJNI.SBBreakpoint_GetThreadID(swigCPtr, this);
  }

  public void SetThreadIndex(long index) {
    lldbJNI.SBBreakpoint_SetThreadIndex(swigCPtr, this, index);
  }

  public long GetThreadIndex() {
    return lldbJNI.SBBreakpoint_GetThreadIndex(swigCPtr, this);
  }

  public void SetThreadName(String thread_name) {
    lldbJNI.SBBreakpoint_SetThreadName(swigCPtr, this, thread_name);
  }

  public String GetThreadName() {
    return lldbJNI.SBBreakpoint_GetThreadName(swigCPtr, this);
  }

  public void SetQueueName(String queue_name) {
    lldbJNI.SBBreakpoint_SetQueueName(swigCPtr, this, queue_name);
  }

  public String GetQueueName() {
    return lldbJNI.SBBreakpoint_GetQueueName(swigCPtr, this);
  }

  public void SetScriptCallbackFunction(String callback_function_name) {
    lldbJNI.SBBreakpoint_SetScriptCallbackFunction__SWIG_0(swigCPtr, this, callback_function_name);
  }

  public SBError SetScriptCallbackFunction(String callback_function_name, SBStructuredData extra_args) {
    return new SBError(lldbJNI.SBBreakpoint_SetScriptCallbackFunction__SWIG_1(swigCPtr, this, callback_function_name, SBStructuredData.getCPtr(extra_args), extra_args), true);
  }

  public SBError SetScriptCallbackBody(String script_body_text) {
    return new SBError(lldbJNI.SBBreakpoint_SetScriptCallbackBody(swigCPtr, this, script_body_text), true);
  }

  public void SetCommandLineCommands(SBStringList commands) {
    lldbJNI.SBBreakpoint_SetCommandLineCommands(swigCPtr, this, SBStringList.getCPtr(commands), commands);
  }

  public boolean GetCommandLineCommands(SBStringList commands) {
    return lldbJNI.SBBreakpoint_GetCommandLineCommands(swigCPtr, this, SBStringList.getCPtr(commands), commands);
  }

  public boolean AddName(String new_name) {
    return lldbJNI.SBBreakpoint_AddName(swigCPtr, this, new_name);
  }

  public SBError AddNameWithErrorHandling(String new_name) {
    return new SBError(lldbJNI.SBBreakpoint_AddNameWithErrorHandling(swigCPtr, this, new_name), true);
  }

  public void RemoveName(String name_to_remove) {
    lldbJNI.SBBreakpoint_RemoveName(swigCPtr, this, name_to_remove);
  }

  public boolean MatchesName(String name) {
    return lldbJNI.SBBreakpoint_MatchesName(swigCPtr, this, name);
  }

  public void GetNames(SBStringList names) {
    lldbJNI.SBBreakpoint_GetNames(swigCPtr, this, SBStringList.getCPtr(names), names);
  }

  public long GetNumResolvedLocations() {
    return lldbJNI.SBBreakpoint_GetNumResolvedLocations(swigCPtr, this);
  }

  public long GetNumLocations() {
    return lldbJNI.SBBreakpoint_GetNumLocations(swigCPtr, this);
  }

  public boolean GetDescription(SBStream description) {
    return lldbJNI.SBBreakpoint_GetDescription__SWIG_0(swigCPtr, this, SBStream.getCPtr(description), description);
  }

  public boolean GetDescription(SBStream description, boolean include_locations) {
    return lldbJNI.SBBreakpoint_GetDescription__SWIG_1(swigCPtr, this, SBStream.getCPtr(description), description, include_locations);
  }

  public SBError AddLocation(SBAddress address) {
    return new SBError(lldbJNI.SBBreakpoint_AddLocation(swigCPtr, this, SBAddress.getCPtr(address), address), true);
  }

  public SBStructuredData SerializeToStructuredData() {
    return new SBStructuredData(lldbJNI.SBBreakpoint_SerializeToStructuredData(swigCPtr, this), true);
  }

  public static boolean EventIsBreakpointEvent(SBEvent event) {
    return lldbJNI.SBBreakpoint_EventIsBreakpointEvent(SBEvent.getCPtr(event), event);
  }

  public static BreakpointEventType GetBreakpointEventTypeFromEvent(SBEvent event) {
    return BreakpointEventType.swigToEnum(lldbJNI.SBBreakpoint_GetBreakpointEventTypeFromEvent(SBEvent.getCPtr(event), event));
  }

  public static SBBreakpoint GetBreakpointFromEvent(SBEvent event) {
    return new SBBreakpoint(lldbJNI.SBBreakpoint_GetBreakpointFromEvent(SBEvent.getCPtr(event), event), true);
  }

  public static SBBreakpointLocation GetBreakpointLocationAtIndexFromEvent(SBEvent event, long loc_idx) {
    return new SBBreakpointLocation(lldbJNI.SBBreakpoint_GetBreakpointLocationAtIndexFromEvent(SBEvent.getCPtr(event), event, loc_idx), true);
  }

  public static long GetNumBreakpointLocationsFromEvent(SBEvent event_sp) {
    return lldbJNI.SBBreakpoint_GetNumBreakpointLocationsFromEvent(SBEvent.getCPtr(event_sp), event_sp);
  }

  public boolean IsHardware() {
    return lldbJNI.SBBreakpoint_IsHardware(swigCPtr, this);
  }

  public String __str__() {
    return lldbJNI.SBBreakpoint___str__(swigCPtr, this);
  }

}
