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
package agent.frida.model.iface2;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;

import agent.frida.manager.FridaReason;
import agent.frida.manager.FridaValue;
import agent.frida.manager.FridaState;
import ghidra.dbg.target.TargetRegisterBank;

public interface FridaModelTargetRegisterBank extends FridaModelTargetObject, TargetRegisterBank {

	public FridaModelTargetRegister getTargetRegister(FridaValue register);

	public default void threadStateChangedSpecific(FridaState state, FridaReason reason) {
		readRegistersNamed(getCachedElements().keySet());
	}

	@Override
	public CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
			Collection<String> names);

	@Override
	public CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values);

	@Override
	public default Map<String, byte[]> getCachedRegisters() {
		return getValues();
	}

	public default Map<String, byte[]> getValues() {
		Map<String, byte[]> result = new HashMap<>();
		for (Entry<String, ?> entry : this.getCachedAttributes().entrySet()) {
			if (entry.getValue() instanceof FridaModelTargetRegister) {
				FridaModelTargetRegister reg = (FridaModelTargetRegister) entry.getValue();
				byte[] bytes = reg.getBytes();
				result.put(entry.getKey(), bytes);
			}
		}
		return result;
	}

}
