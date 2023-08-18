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
package ghidra.app.plugin.core.debug.service.rmi.trace;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.SocketAddress;

public class TraceRmiAcceptor extends TraceRmiServer {

	public TraceRmiAcceptor(TraceRmiPlugin plugin, SocketAddress address) {
		super(plugin, address);
	}

	@Override
	public void start() throws IOException {
		socket = new ServerSocket();
		bind();
	}

	@Override
	protected void bind() throws IOException {
		socket.bind(address, 1);
	}

	@Override
	public TraceRmiHandler accept() throws IOException {
		TraceRmiHandler handler = super.accept();
		close();
		return handler;
	}
}
