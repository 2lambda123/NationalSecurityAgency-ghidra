/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package agent.dbgeng.model.iface1;

import agent.dbgeng.manager.breakpoint.DbgBreakpointInfo;
import agent.dbgeng.model.iface2.DbgModelTargetObject;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointAction;
import ghidra.util.datastruct.ListenerSet;

/**
 * An interface which indicates this object is capable of launching targets.
 * 
 * The targets this launcher creates ought to appear in its successors.
 * 
 * @param <T> type for this
 */
public interface DbgModelTargetBptHelper extends DbgModelTargetObject {

	public DbgBreakpointInfo getBreakpointInfo();

	public void setBreakpointId(String id);

	public void setBreakpointInfo(DbgBreakpointInfo info);

	public boolean isBreakpointEnabled();

	public void setBreakpointEnabled(boolean enabled);

	public ListenerSet<TargetBreakpointAction> getActions();

}
