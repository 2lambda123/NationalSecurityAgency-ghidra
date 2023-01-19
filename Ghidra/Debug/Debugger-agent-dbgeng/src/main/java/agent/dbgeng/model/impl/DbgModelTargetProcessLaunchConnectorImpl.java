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
package agent.dbgeng.model.impl;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.model.iface2.DbgModelTargetConnector;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "ProcessLaunchConnector",
	elements = { //
		@TargetElementType(type = Void.class) //
	},
	attributes = { //
		@TargetAttributeType(type = Void.class) //
	})
public class DbgModelTargetProcessLaunchConnectorImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetConnector {

	protected final DbgModelTargetConnectorContainerImpl connectors;
	protected final TargetParameterMap paramDescs;

	public DbgModelTargetProcessLaunchConnectorImpl(DbgModelTargetConnectorContainerImpl connectors,
			String name) {
		super(connectors.getModel(), connectors, name, name);
		this.connectors = connectors;

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME,
			paramDescs = TargetParameterMap.copyOf(computeParameters()) //
		), "Initialized");
	}

	@Override
	public CompletableFuture<Void> setActive() {
		connectors.setDefaultConnector(this);
		return CompletableFuture.completedFuture(null);
	}

	protected Map<String, ParameterDescription<?>> computeParameters() {
		HashMap<String, ParameterDescription<?>> map =
			new HashMap<String, ParameterDescription<?>>();
		ParameterDescription<String> param = ParameterDescription.create(String.class, "args", true,
			null, "Cmd", "executable to be launched");
		ParameterDescription<String> initDir =
			ParameterDescription.create(String.class, "dir", false,
				null, "Dir", "initial directory");
		ParameterDescription<String> env = ParameterDescription.create(String.class, "env", false,
			null, "Env (sep=/0)", "environment block");
		ParameterDescription<Integer> cf = ParameterDescription.create(Integer.class, "cf", true,
			1, "Create Flags", "creation flags");
		ParameterDescription<Integer> ef = ParameterDescription.create(Integer.class, "ef", false,
			0, "Create Flags (Eng)", "engine creation flags");
		ParameterDescription<Integer> vf = ParameterDescription.create(Integer.class, "vf", false,
			0, "Verifier Flags", "verifier flags");
		map.put("args", param);
		map.put("dir", initDir);
		map.put("env", env);
		map.put("cf", cf);
		map.put("ef", ef);
		map.put("vf", vf);
		// Innocuous comment: up-up-down-down-left-right-left-right-B-A
		return map;
	}

	@Override
	public TargetParameterMap getParameters() {
		return TargetMethod.getParameters(this);
	}

	@Override
	public CompletableFuture<Void> launch(Map<String, ?> args) {
		return getManager().launch(args);
	}

}
