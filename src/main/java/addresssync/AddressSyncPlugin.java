/*
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
package addresssync;


import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;


//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "AddressSync",
	category = PluginCategoryNames.SELECTION,
	shortDescription = "Synchronize currently selected address to external program",
	description = "Listens on 127.0.0.1:1080 (UDP) for 64-bit address and sets Listing and Decompiler cursor position to specified address."
)
//@formatter:on
public class AddressSyncPlugin extends ProgramPlugin {

	SyncServer server;

	/**
	 * Plugin constructor.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public AddressSyncPlugin(PluginTool tool) {
		super(tool, true, true);
		server = new SyncServer(tool, 1080);
	}

	@Override
	public void init() {
		super.init();
		server.start();
	}

	@Override
	protected void locationChanged(ProgramLocation loc)
	{
		if (loc != null) {
			server.setCurrentProgram(loc.getProgram());
		} else {
			server.setCurrentProgram(null);
		}
	}
}
