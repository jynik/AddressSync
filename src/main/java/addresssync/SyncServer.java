package addresssync;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;

import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Program;

public class SyncServer extends Thread {
	private PluginTool plugin;
	private Program currProgram;
	private int port;

	public SyncServer(PluginTool plugin, int port) {
		this.plugin = plugin;
		this.port = port;
		this.currProgram = null;
	}

	public void setCurrentProgram(Program p) {
		this.currProgram = p;
	}

	@SuppressWarnings("resource")
	public void run() {
		// We'll always operate on 64-bit little endian addresses.
		byte[] addrBuf = new byte[8];
		long address;

		DatagramSocket sock;

		try {
			sock = new DatagramSocket(null);
			InetSocketAddress sockAddr = new InetSocketAddress("localhost", this.port);
			sock.bind(sockAddr);
		} catch (SocketException e) {
			e.printStackTrace();
			return;
		}

		while (true) {
			DatagramPacket pkt = new DatagramPacket(addrBuf, addrBuf.length);
			try {
				sock.receive(pkt);
				address =   (addrBuf[0] & 0xff)	        |
					       ((addrBuf[1] & 0xff) << 8)   |
					       ((addrBuf[2] & 0xff) << 16)  |
					       ((addrBuf[3] & 0xff) << 24)  |
					       ((addrBuf[4] & 0xff) << 32)  |
					       ((addrBuf[5] & 0xff) << 40)  |
					       ((addrBuf[6] & 0xff) << 48)  |
					       ((addrBuf[7] & 0xff) << 56);

				// FIXME: Race condition on this access
				if (this.currProgram == null) {
					continue;
				}

				try {
					Address loc = this.currProgram.getImageBase().add(address);
					this.plugin.getService(GoToService.class).goTo(loc);
				} catch (AddressOutOfBoundsException e) {
					System.err.printf("[AddressSync] Could not set address: 0x%08x\n", address);
					// System.err.println(e.getMessage());
				}

			} catch (IOException e) {
				e.printStackTrace();
			} catch (NullPointerException e) {
				e.printStackTrace();
			}
		}
	}
}
