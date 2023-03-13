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
package agent.dbgeng.model.iface2;

import java.util.concurrent.CompletableFuture;

import agent.dbgeng.manager.DbgModuleMemory;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.target.TargetMemory;
import ghidra.program.model.address.Address;

public interface DbgModelTargetMemoryContainer extends DbgModelTargetObject, TargetMemory {

	public DbgModelTargetMemoryRegion getTargetMemory(DbgModuleMemory region);

	@Override
	public CompletableFuture<byte[]> readMemory(Address address, int length);

	@Override
	public CompletableFuture<Void> writeMemory(Address address, byte[] data);

	public CompletableFuture<Void> requestElements(RefreshBehavior refresh);

}
