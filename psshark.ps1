<#PSScriptInfo
.VERSION 1.0
.GUID ff783128-b039-4ea8-a0ef-49de6318807b
.AUTHOR MeCRO-DEV
.COMPANYNAME MeCRO
.COPYRIGHT MeCRO-DEV
.TAGS Wireshark packet capture network WPF
.LICENSEURI
.PROJECTURI
.ICONURI
.EXTERNALMODULEDEPENDENCIES NetEventPacketCapture
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
v1.0 - First release
  Capture
   - Live capture through the NetEventPacketCapture module (real-time ETW), run as Administrator.
   - Capture Options: interface list with IPv4, promiscuous mode, optional "Only capture filtered packets".
   - Start/Stop/Restart; the title bar shows the interface and (filtered)/(unfiltered).
  Files
   - Opens pcap and pcapng (Wireshark files); saves pcap that Wireshark can open; drag and drop to open.
   - Save As also offers Text (.txt): every row in the table as a pktmon "etl2txt" style log (timestamp/PktGroupId header line plus the
     packet decoded in tcpdump format); respects the display filter. Verified line-for-line against pktmon hex2pkt.
  Display
   - Wireshark layout and menus (File, Edit, View, Go, Capture, Help); no Analyze/Statistics/Telephony/Wireless/Tools.
   - Packet list columns: No., Time, Source, Destination, Protocol, Length, Info (IP addresses only, no DNS lookups).
   - Wireshark-format packet decode tree with byte highlighting, and a hex/ASCII pane.
   - Right-click a packet-details line that holds MAC or IP addresses to copy them (Copy source/destination MAC or IP).
   - TCP reassembly (as Wireshark shows it): a message split over several segments is decoded on its last segment, with a
     "[N Reassembled TCP Segments ...]" tree entry; HTTP (Content-Length and chunked bodies), TLS records, DNS over TCP.
   - Protocols: Ethernet, 802.1Q, ARP, STP, IPv4/IPv6, ICMP/ICMPv6, IGMP, TCP, UDP, DNS (UDP and TCP), mDNS,
     LLMNR, DHCP, SSDP, HTTP, TLS; Wi-Fi (802.11) frames are only labelled.
   - Filter language (display filter and capture filter) modelled on Wireshark's: 166 typed fields for the decoded protocols
     (frame, eth, vlan, arp, ip, ipv6, icmp, igmp, tcp, udp, dns, dhcp, http, tls), operators == != > < >= <= eq ne gt lt ge le,
     contains, matches (regex), in {a, b, lo..hi}, bit tests (&), slices (eth.src[0:3], tcp[13]), CIDR (ip.addr == 10.0.0.0/8),
     any/all quantifiers, === and !==, && || ^^ ! and parentheses. Results were compared with tshark on Wireshark's sample captures.
   - Filter boxes check syntax as you type (green = valid, red = error; hover for the reason). Apply/Enter shows a dialog that
     says what is wrong and where, with "did you mean" suggestions for misspelled fields.
  Design
   - Resizable window, dark scrolling panes, embedded green application icon (all-in-one script).
   - Background runspaces keep the UI responsive; tested with 400,000+ packets.
  Known limits
   - No TLS decryption; TCP reassembly covers HTTP/1.x, TLS records and DNS over TCP only (no HTTP/2, no SMB, ...).
   - Filters cover the fields PSShark decodes (not every Wireshark field); no functions (len(), upper()...) or arithmetic;
     the packet quoted inside ICMP error messages is not decoded, so its addresses/ports do not match filters.
   - Live capture requires Administrator rights and Windows.
#>

<#
.SYNOPSIS
 PSShark - a Wireshark-style packet capture viewer written in PowerShell (WPF + runspaces).

.DESCRIPTION
 Live capture uses the NetEventPacketCapture module (run as Administrator).
 Reads pcap/pcapng files and saves pcap files that Wireshark can open.
 This is an all-in-one script: the C# dissector, XAML and the application icon are embedded.

.PARAMETER OpenFile
 Optional capture file (.pcap / .pcapng) to open at start-up.

.PARAMETER ShowConsole
 Keep the console window visible (it is hidden by default when the script owns it).

.PARAMETER Screenshot
 Developer aid: after loading -OpenFile, render the window to this PNG file and exit.

.PARAMETER SelectPacket
 Developer aid (with -Screenshot): packet number to select before rendering.

.PARAMETER DisplayFilter
 Developer aid (with -Screenshot): display filter to apply before rendering.
#>
############################################################################
# PSShark (Wireshark PowerShell Version)
# GUI theme follows PSPigeon (same author).
############################################################################
#Requires -Version 5.1
[CmdletBinding()]
param (
    [Parameter(Position = 0)] [string] $OpenFile,
    [switch] $ShowConsole,
    [string] $Screenshot,
    [int] $SelectPacket = 0,
    [string] $DisplayFilter = ''
)
Set-StrictMode -Version Latest

# Arguments to forward when the script has to restart itself in a fresh process.
$fwd = @()
foreach ($k in $PSBoundParameters.Keys) {
    $v = $PSBoundParameters[$k]
    if ($v -is [switch]) { if ($v.IsPresent) { $fwd += "-$k" } }
    else { $fwd += "-$k"; $fwd += "$v" }
}

# WPF needs a single-threaded apartment: relaunch in STA if necessary.
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    & (Get-Process -Id $PID).Path -NoProfile -STA -ExecutionPolicy Bypass -File $PSCommandPath @fwd
    exit $LASTEXITCODE
}

# Hide the console window when this script is the only process attached to it.
if (-not $ShowConsole) {
    try {
        Add-Type -Namespace PSSharkNative -Name Win -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("kernel32.dll")] public static extern uint GetConsoleProcessList(uint[] list, uint count);
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
'@ -ErrorAction Stop
        $h = [PSSharkNative.Win]::GetConsoleWindow()
        if ($h -ne [IntPtr]::Zero) {
            $procs = New-Object 'uint32[]' 2
            if ([PSSharkNative.Win]::GetConsoleProcessList($procs, 2) -le 1) { [void][PSSharkNative.Win]::ShowWindow($h, 0) }
        }
    }
    catch { }
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml

############################################################################
# Compiled core: packet model, Wireshark-style dissector, pcap/pcapng I/O,
# display filter, hex dump and the real-time ETW consumer (NetEventPacketCapture).
############################################################################
$script:csharp = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace PSShark
{
    // ---------------------------------------------------------------- models
    public class RawPacket
    {
        public long Ticks;      // 100ns units since 0001-01-01 UTC (DateTime ticks)
        public byte[] Data;
        public int OrigLen;
        public int LinkType;    // pcap LINKTYPE_*
        public string IfName;
        public string IfDesc;
        public int Dir;         // 0 unknown, 1 sent (Tx), 2 received (Rx)
    }

    public class SharedState
    {
        public volatile bool Cancel;
        public volatile bool Done;
        public long Progress;
        public long Total;
        public long Count;
        public string Status;
        public string Error;
    }

    public class Packet
    {
        public int No { get; set; }
        public string Time { get; set; }
        public string Source { get; set; }
        public string Destination { get; set; }
        public string Protocol { get; set; }
        public int Length { get; set; }
        public string Info { get; set; }
        public string Bg { get; set; }
        public string Fg { get; set; }

        public byte[] Data;
        public long Ticks;
        public int OrigLen;
        public int LinkType;
        public string IfName;
        public string IfDesc;
        public int Dir;
        public long SinceFirst;
        public long DeltaPrev;
        public string Chain = "";
        public string RuleName = "";
        public string RuleExpr = "";

        // transport analysis, filled by the stateful pass
        public string SrcIp, DstIp;
        public int SrcPort, DstPort;
        public uint RelSeq, RelAck;
        public int StreamIdx = -1;
        public int WinScale = -1;
        public string TcpNote;
        public bool Analysed;
        public uint OppBase;
        public bool HasOpp;
        public int Ttl;
        public string TlsProto;
        public bool TlsEncStart, Tls13Start;

        // layer positions recorded by the dissector (used by the filter engine)
        public int EthOff = -1, EthType = -1, VlanId = -1, VlanPri;
        public int L3Off = -1, L3Ver, L3End, L4Off = -1, L4End, L4Proto, PayOff = -1, PayEnd, ArpOff = -1;
        public Dictionary<string, List<object>> App;      // DNS / HTTP / TLS / DHCP values, by Wireshark field name

        // TCP reassembly
        public byte[] ReasmData;                          // assembled PDU(s) completed by this frame
        public int ReasmKind;                             // 1 HTTP, 2 TLS, 3 DNS
        public int ReasmPduLen;                           // length of the PDU that spanned several segments (ReasmData may hold more)
        public int[] ReasmNos, ReasmLens;                 // frames (and bytes each) that make up ReasmData
        public int ReasmOwnOff, ReasmOwnStart, ReasmOwnLen;   // where this frame's own bytes sit (frame data / assembled data)
        public int ReasmIn;                               // earlier segments: the frame that completes the PDU
        public bool SegOfPdu;                             // carries part of a PDU that is not complete in this frame
        public int DEnd;                                  // end of the complete part dissected on its own (0 = whole payload)
        public void AddApp(string key, object value)
        {
            if (App == null) App = new Dictionary<string, List<object>>();
            List<object> l;
            if (!App.TryGetValue(key, out l)) { l = new List<object>(2); App[key] = l; }
            l.Add(value);
        }

        string text;
        public string Text
        {
            get
            {
                if (text == null)
                    text = No + " " + Time + " " + Source + " " + Destination + " " + Protocol + " " + Length + " " + Info;
                return text;
            }
        }

        public Packet Copy() { return (Packet)MemberwiseClone(); }
    }

    public class TreeNode
    {
        public string Text { get; set; }
        public int Start;
        public int Length;
        public List<TreeNode> Children { get; set; }
        public bool Expanded { get; set; }
        public TreeNode(string t, int s, int l) { Text = t; Start = s; Length = l; Children = new List<TreeNode>(); }

        public static void SetAll(List<TreeNode> nodes, bool expanded)
        {
            if (nodes == null) return;
            foreach (TreeNode n in nodes) { n.Expanded = expanded; SetAll(n.Children, expanded); }
        }
    }

    public class HexSeg
    {
        public string Text { get; set; }
        public bool Hl { get; set; }
    }

    // --------------------------------------------------- list with batch drain
    public class PacketStore : ObservableCollection<Packet>
    {
        public readonly List<Packet> All = new List<Packet>();
        public Predicate<Packet> Filter;

        public int Drain(ConcurrentQueue<Packet> q, int budgetMs)
        {
            Stopwatch sw = Stopwatch.StartNew();
            int n = 0;
            Packet p;
            while (q.TryDequeue(out p))
            {
                All.Add(p);
                if (Filter == null || Filter(p)) Add(p);
                n++;
                if ((n & 63) == 0 && sw.ElapsedMilliseconds >= budgetMs) break;
            }
            return n;
        }

        // Index of the next displayed row (after `start`) whose text contains `needle`, wrapping around; -1 if none.
        public int Find(int start, string needle, bool forward)
        {
            int n = Count;
            if (n == 0 || string.IsNullOrEmpty(needle)) return -1;
            for (int k = 1; k <= n; k++)
            {
                int i = forward ? (start + k) % n : (((start - k) % n) + n) % n;
                if (this[i].Text.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) return i;
            }
            return -1;
        }

        public int IndexOfNo(int no)
        {
            int lo = 0, hi = Count - 1;
            while (lo <= hi)
            {
                int mid = (lo + hi) / 2;
                int v = this[mid].No;
                if (v == no) return mid;
                if (v < no) lo = mid + 1; else hi = mid - 1;
            }
            return -1;
        }

        // A copy of the rows the table is showing (respects the display filter).
        public List<Packet> Displayed() { return new List<Packet>(this); }

        public void Refilter()
        {
            List<Packet> keep = new List<Packet>();
            for (int i = 0; i < All.Count; i++)
                if (Filter == null || Filter(All[i])) keep.Add(All[i]);
            Items.Clear();
            for (int i = 0; i < keep.Count; i++) Items.Add(keep[i]);
            OnPropertyChanged(new PropertyChangedEventArgs("Count"));
            OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
            OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
        }

        public void Reset()
        {
            All.Clear();
            Items.Clear();
            OnPropertyChanged(new PropertyChangedEventArgs("Count"));
            OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
            OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
        }
    }

    // ------------------------------------------------------------ filter language (Wireshark display-filter subset)
    public enum FT { Uint, Bool, Ipv4, Ipv6, Mac, Str, Bytes, Float }

    public class FieldDef
    {
        public string Name;
        public FT Type;
        public Action<Packet, List<object>> Get;    // appends every instance of the field found in the packet
        public long Max = long.MaxValue;            // largest value the field can hold (for literal checks)
    }

    public class FilterSyntaxException : Exception
    {
        public int Pos;
        public FilterSyntaxException(string msg, int pos) : base(msg + " (at position " + (pos + 1) + ")") { Pos = pos; }
    }

    // ---- field registry: typed fields read straight from the packet bytes / dissector results
    public static class Fields
    {
        public static readonly Dictionary<string, FieldDef> Map = new Dictionary<string, FieldDef>();
        static readonly long EpochTicks = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).Ticks;

        static void Add(string name, FT t, Action<Packet, List<object>> g)
        {
            FieldDef f = new FieldDef(); f.Name = name; f.Type = t; f.Get = g; Map[name] = f;
        }
        static void App(string name, FT t)    // values recorded by the dissector (DNS, HTTP, TLS, DHCP)
        {
            Add(name, t, delegate(Packet p, List<object> v)
            {
                List<object> l;
                if (p.App != null && p.App.TryGetValue(name, out l)) v.AddRange(l);
            });
        }

        static long M(byte[] d, int o) { return ((long)d[o] << 40) | ((long)d[o + 1] << 32) | ((long)d[o + 2] << 24) | ((long)d[o + 3] << 16) | ((long)d[o + 4] << 8) | d[o + 5]; }
        static bool Room(Packet p, int off, int n) { return off >= 0 && off + n <= p.Data.Length; }
        static bool Ip4(Packet p) { return p.L3Ver == 4 && Room(p, p.L3Off, 20); }
        static bool Ip6(Packet p) { return p.L3Ver == 6 && Room(p, p.L3Off, 40); }
        static bool Tcp(Packet p) { return p.L4Proto == 6 && Room(p, p.L4Off, 20); }
        static bool Udp(Packet p) { return p.L4Proto == 17 && Room(p, p.L4Off, 8); }
        static bool Icmp(Packet p) { return p.L4Proto == 1 && Room(p, p.L4Off, 4); }
        static bool Icmp6(Packet p) { return p.L4Proto == 58 && Room(p, p.L4Off, 4); }
        static int TcpFlags(Packet p) { return ((p.Data[p.L4Off + 12] & 0x0F) << 8) | p.Data[p.L4Off + 13]; }
        static long B(bool b) { return b ? 1 : 0; }

        static void TcpFlag(string name, int mask)
        {
            Add("tcp.flags." + name, FT.Bool, delegate(Packet p, List<object> v) { if (Tcp(p)) v.Add(B((TcpFlags(p) & mask) != 0)); });
        }

        // TCP option lookup (kind -> start offset)
        static bool TcpOpt(Packet p, int kind, out int off)
        {
            off = -1;
            if (!Tcp(p)) return false;
            int hl = (p.Data[p.L4Off + 12] >> 4) * 4;
            if (hl <= 20) return false;
            Dissector.TcpOpts o = Dissector.ScanOpts(p.Data, p.L4Off + 20, p.L4Off + hl);
            foreach (OptEntry e in o.E) if (e.Kind == kind) { off = e.Start; return true; }
            return false;
        }

        public static bool LayerRange(string name, Packet p, out int off, out int end)
        {
            off = 0; end = p.Data.Length;
            switch (name)
            {
                case "frame": return true;
                case "eth": return p.EthOff >= 0;
                case "ip": if (p.L3Ver != 4) return false; off = p.L3Off; end = p.L3End; return off >= 0;
                case "ipv6": if (p.L3Ver != 6) return false; off = p.L3Off; end = p.L3End; return off >= 0;
                case "tcp": if (p.L4Proto != 6) return false; off = p.L4Off; end = p.L4End; return off >= 0;
                case "udp": if (p.L4Proto != 17) return false; off = p.L4Off; end = p.L4End; return off >= 0;
                case "icmp": if (p.L4Proto != 1) return false; off = p.L4Off; end = p.L4End; return off >= 0;
                case "icmpv6": if (p.L4Proto != 58) return false; off = p.L4Off; end = p.L4End; return off >= 0;
                case "arp": off = p.ArpOff; end = off + 28; return off >= 0;
            }
            return false;
        }

        static Fields()
        {
            // ---- frame and packet-list columns
            Add("frame", FT.Bytes, delegate(Packet p, List<object> v) { v.Add(p.Data); });
            Add("frame.number", FT.Uint, delegate(Packet p, List<object> v) { v.Add((long)p.No); });
            Add("frame.len", FT.Uint, delegate(Packet p, List<object> v) { v.Add((long)p.OrigLen); });
            Add("frame.cap_len", FT.Uint, delegate(Packet p, List<object> v) { v.Add((long)p.Data.Length); });
            Add("frame.time_epoch", FT.Float, delegate(Packet p, List<object> v) { v.Add((p.Ticks - EpochTicks) / 10000000.0); });
            Add("frame.time_delta", FT.Float, delegate(Packet p, List<object> v) { v.Add(p.DeltaPrev / 10000000.0); });
            Add("frame.time_relative", FT.Float, delegate(Packet p, List<object> v) { v.Add(p.SinceFirst / 10000000.0); });
            Add("frame.protocols", FT.Str, delegate(Packet p, List<object> v) { v.Add(p.Chain); });
            Add("frame.interface_name", FT.Str, delegate(Packet p, List<object> v) { if (!string.IsNullOrEmpty(p.IfName)) v.Add(p.IfName); });
            Add("_ws.col.protocol", FT.Str, delegate(Packet p, List<object> v) { v.Add(p.Protocol ?? ""); });
            Add("_ws.col.info", FT.Str, delegate(Packet p, List<object> v) { v.Add(p.Info ?? ""); });
            Add("_ws.col.source", FT.Str, delegate(Packet p, List<object> v) { v.Add(p.Source ?? ""); });
            Add("_ws.col.destination", FT.Str, delegate(Packet p, List<object> v) { v.Add(p.Destination ?? ""); });
            Map["info"] = Map["_ws.col.info"];       // convenience alias

            // ---- ethernet / vlan
            Add("eth.dst", FT.Mac, delegate(Packet p, List<object> v) { if (p.EthOff >= 0 && Room(p, 0, 14)) v.Add(M(p.Data, 0)); });
            Add("eth.src", FT.Mac, delegate(Packet p, List<object> v) { if (p.EthOff >= 0 && Room(p, 0, 14)) v.Add(M(p.Data, 6)); });
            Add("eth.addr", FT.Mac, delegate(Packet p, List<object> v) { if (p.EthOff >= 0 && Room(p, 0, 14)) { v.Add(M(p.Data, 0)); v.Add(M(p.Data, 6)); } });
            Add("eth.type", FT.Uint, delegate(Packet p, List<object> v) { if (p.EthType >= 0) v.Add((long)p.EthType); });
            Add("eth.len", FT.Uint, delegate(Packet p, List<object> v) { if (p.EthOff >= 0 && p.EthType < 0 && Room(p, 12, 2)) v.Add((long)U.W(p.Data, 12)); });
            Add("vlan.id", FT.Uint, delegate(Packet p, List<object> v) { if (p.VlanId >= 0) v.Add((long)p.VlanId); });
            Add("vlan.priority", FT.Uint, delegate(Packet p, List<object> v) { if (p.VlanId >= 0) v.Add((long)p.VlanPri); });

            // ---- ARP
            Add("arp.hw.type", FT.Uint, delegate(Packet p, List<object> v) { if (Room(p, p.ArpOff, 28)) v.Add((long)U.W(p.Data, p.ArpOff)); });
            Add("arp.proto.type", FT.Uint, delegate(Packet p, List<object> v) { if (Room(p, p.ArpOff, 28)) v.Add((long)U.W(p.Data, p.ArpOff + 2)); });
            Add("arp.hw.size", FT.Uint, delegate(Packet p, List<object> v) { if (Room(p, p.ArpOff, 28)) v.Add((long)p.Data[p.ArpOff + 4]); });
            Add("arp.proto.size", FT.Uint, delegate(Packet p, List<object> v) { if (Room(p, p.ArpOff, 28)) v.Add((long)p.Data[p.ArpOff + 5]); });
            Add("arp.opcode", FT.Uint, delegate(Packet p, List<object> v) { if (Room(p, p.ArpOff, 28)) v.Add((long)U.W(p.Data, p.ArpOff + 6)); });
            Add("arp.src.hw_mac", FT.Mac, delegate(Packet p, List<object> v) { if (Room(p, p.ArpOff, 28)) v.Add(M(p.Data, p.ArpOff + 8)); });
            Add("arp.src.proto_ipv4", FT.Ipv4, delegate(Packet p, List<object> v) { if (Room(p, p.ArpOff, 28)) v.Add((long)U.L(p.Data, p.ArpOff + 14)); });
            Add("arp.dst.hw_mac", FT.Mac, delegate(Packet p, List<object> v) { if (Room(p, p.ArpOff, 28)) v.Add(M(p.Data, p.ArpOff + 18)); });
            Add("arp.dst.proto_ipv4", FT.Ipv4, delegate(Packet p, List<object> v) { if (Room(p, p.ArpOff, 28)) v.Add((long)U.L(p.Data, p.ArpOff + 24)); });

            // ---- IPv4
            Add("ip.version", FT.Uint, delegate(Packet p, List<object> v) { if (Ip4(p)) v.Add((long)(p.Data[p.L3Off] >> 4)); });
            Add("ip.hdr_len", FT.Uint, delegate(Packet p, List<object> v) { if (Ip4(p)) v.Add((long)((p.Data[p.L3Off] & 0xF) * 4)); });
            Add("ip.dsfield", FT.Uint, delegate(Packet p, List<object> v) { if (Ip4(p)) v.Add((long)p.Data[p.L3Off + 1]); });
            Add("ip.dsfield.dscp", FT.Uint, delegate(Packet p, List<object> v) { if (Ip4(p)) v.Add((long)(p.Data[p.L3Off + 1] >> 2)); });
            Add("ip.dsfield.ecn", FT.Uint, delegate(Packet p, List<object> v) { if (Ip4(p)) v.Add((long)(p.Data[p.L3Off + 1] & 3)); });
            Add("ip.len", FT.Uint, delegate(Packet p, List<object> v) { if (Ip4(p)) v.Add((long)U.W(p.Data, p.L3Off + 2)); });
            Add("ip.id", FT.Uint, delegate(Packet p, List<object> v) { if (Ip4(p)) v.Add((long)U.W(p.Data, p.L3Off + 4)); });
            Add("ip.flags", FT.Uint, delegate(Packet p, List<object> v) { if (Ip4(p)) v.Add((long)(U.W(p.Data, p.L3Off + 6) >> 13)); });
            Add("ip.flags.rb", FT.Bool, delegate(Packet p, List<object> v) { if (Ip4(p)) v.Add(B((U.W(p.Data, p.L3Off + 6) & 0x8000) != 0)); });
            Add("ip.flags.df", FT.Bool, delegate(Packet p, List<object> v) { if (Ip4(p)) v.Add(B((U.W(p.Data, p.L3Off + 6) & 0x4000) != 0)); });
            Add("ip.flags.mf", FT.Bool, delegate(Packet p, List<object> v) { if (Ip4(p)) v.Add(B((U.W(p.Data, p.L3Off + 6) & 0x2000) != 0)); });
            Add("ip.frag_offset", FT.Uint, delegate(Packet p, List<object> v) { if (Ip4(p)) v.Add((long)((U.W(p.Data, p.L3Off + 6) & 0x1FFF) * 8)); });
            Add("ip.ttl", FT.Uint, delegate(Packet p, List<object> v) { if (Ip4(p)) v.Add((long)p.Data[p.L3Off + 8]); });
            Add("ip.proto", FT.Uint, delegate(Packet p, List<object> v) { if (Ip4(p)) v.Add((long)p.Data[p.L3Off + 9]); });
            Add("ip.checksum", FT.Uint, delegate(Packet p, List<object> v) { if (Ip4(p)) v.Add((long)U.W(p.Data, p.L3Off + 10)); });
            Add("ip.src", FT.Ipv4, delegate(Packet p, List<object> v) { if (Ip4(p)) v.Add((long)U.L(p.Data, p.L3Off + 12)); });
            Add("ip.dst", FT.Ipv4, delegate(Packet p, List<object> v) { if (Ip4(p)) v.Add((long)U.L(p.Data, p.L3Off + 16)); });
            Add("ip.addr", FT.Ipv4, delegate(Packet p, List<object> v) { if (Ip4(p)) { v.Add((long)U.L(p.Data, p.L3Off + 12)); v.Add((long)U.L(p.Data, p.L3Off + 16)); } });

            // ---- IPv6
            Add("ipv6.version", FT.Uint, delegate(Packet p, List<object> v) { if (Ip6(p)) v.Add((long)(p.Data[p.L3Off] >> 4)); });
            Add("ipv6.tclass", FT.Uint, delegate(Packet p, List<object> v) { if (Ip6(p)) v.Add((long)(((p.Data[p.L3Off] & 0xF) << 4) | (p.Data[p.L3Off + 1] >> 4))); });
            Add("ipv6.flow", FT.Uint, delegate(Packet p, List<object> v) { if (Ip6(p)) v.Add((long)(U.L(p.Data, p.L3Off) & 0xFFFFF)); });
            Add("ipv6.plen", FT.Uint, delegate(Packet p, List<object> v) { if (Ip6(p)) v.Add((long)U.W(p.Data, p.L3Off + 4)); });
            Add("ipv6.nxt", FT.Uint, delegate(Packet p, List<object> v) { if (Ip6(p)) v.Add((long)p.Data[p.L3Off + 6]); });
            Add("ipv6.hlim", FT.Uint, delegate(Packet p, List<object> v) { if (Ip6(p)) v.Add((long)p.Data[p.L3Off + 7]); });
            Add("ipv6.src", FT.Ipv6, delegate(Packet p, List<object> v) { if (Ip6(p)) { byte[] b = new byte[16]; Array.Copy(p.Data, p.L3Off + 8, b, 0, 16); v.Add(b); } });
            Add("ipv6.dst", FT.Ipv6, delegate(Packet p, List<object> v) { if (Ip6(p)) { byte[] b = new byte[16]; Array.Copy(p.Data, p.L3Off + 24, b, 0, 16); v.Add(b); } });
            Add("ipv6.addr", FT.Ipv6, delegate(Packet p, List<object> v)
            {
                if (Ip6(p))
                {
                    byte[] a = new byte[16], b = new byte[16];
                    Array.Copy(p.Data, p.L3Off + 8, a, 0, 16); Array.Copy(p.Data, p.L3Off + 24, b, 0, 16);
                    v.Add(a); v.Add(b);
                }
            });

            // ---- ICMP / ICMPv6 / IGMP
            Add("icmp.type", FT.Uint, delegate(Packet p, List<object> v) { if (Icmp(p)) v.Add((long)p.Data[p.L4Off]); });
            Add("icmp.code", FT.Uint, delegate(Packet p, List<object> v) { if (Icmp(p)) v.Add((long)p.Data[p.L4Off + 1]); });
            Add("icmp.checksum", FT.Uint, delegate(Packet p, List<object> v) { if (Icmp(p)) v.Add((long)U.W(p.Data, p.L4Off + 2)); });
            Add("icmp.ident", FT.Uint, delegate(Packet p, List<object> v) { if (Icmp(p) && Room(p, p.L4Off, 8) && (p.Data[p.L4Off] == 0 || p.Data[p.L4Off] == 8)) v.Add((long)U.W(p.Data, p.L4Off + 4)); });
            Add("icmp.seq", FT.Uint, delegate(Packet p, List<object> v) { if (Icmp(p) && Room(p, p.L4Off, 8) && (p.Data[p.L4Off] == 0 || p.Data[p.L4Off] == 8)) v.Add((long)U.W(p.Data, p.L4Off + 6)); });
            Add("icmpv6.type", FT.Uint, delegate(Packet p, List<object> v) { if (Icmp6(p)) v.Add((long)p.Data[p.L4Off]); });
            Add("icmpv6.code", FT.Uint, delegate(Packet p, List<object> v) { if (Icmp6(p)) v.Add((long)p.Data[p.L4Off + 1]); });
            Add("igmp.type", FT.Uint, delegate(Packet p, List<object> v) { if (p.L4Proto == 2 && Room(p, p.L4Off, 8)) v.Add((long)p.Data[p.L4Off]); });
            Add("igmp.maddr", FT.Ipv4, delegate(Packet p, List<object> v) { if (p.L4Proto == 2 && Room(p, p.L4Off, 8) && p.Data[p.L4Off] != 0x22) v.Add((long)U.L(p.Data, p.L4Off + 4)); });

            // ---- TCP
            Add("tcp.srcport", FT.Uint, delegate(Packet p, List<object> v) { if (Tcp(p)) v.Add((long)U.W(p.Data, p.L4Off)); });
            Add("tcp.dstport", FT.Uint, delegate(Packet p, List<object> v) { if (Tcp(p)) v.Add((long)U.W(p.Data, p.L4Off + 2)); });
            Add("tcp.port", FT.Uint, delegate(Packet p, List<object> v) { if (Tcp(p)) { v.Add((long)U.W(p.Data, p.L4Off)); v.Add((long)U.W(p.Data, p.L4Off + 2)); } });
            Add("tcp.stream", FT.Uint, delegate(Packet p, List<object> v) { if (Tcp(p) && p.StreamIdx >= 0) v.Add((long)p.StreamIdx); });
            Add("tcp.len", FT.Uint, delegate(Packet p, List<object> v) { if (Tcp(p)) v.Add((long)Math.Max(0, p.PayEnd - p.PayOff)); });
            Add("tcp.seq", FT.Uint, delegate(Packet p, List<object> v) { if (Tcp(p)) v.Add((long)p.RelSeq); });
            Add("tcp.seq_raw", FT.Uint, delegate(Packet p, List<object> v) { if (Tcp(p)) v.Add((long)U.L(p.Data, p.L4Off + 4)); });
            Add("tcp.nxtseq", FT.Uint, delegate(Packet p, List<object> v)
            {
                if (Tcp(p)) { int f = TcpFlags(p); v.Add((long)(uint)(p.RelSeq + (uint)Math.Max(0, p.PayEnd - p.PayOff) + (uint)(((f & 2) != 0 ? 1 : 0) + ((f & 1) != 0 ? 1 : 0)))); }
            });
            Add("tcp.ack", FT.Uint, delegate(Packet p, List<object> v) { if (Tcp(p)) v.Add((TcpFlags(p) & 0x10) != 0 ? (long)p.RelAck : 0L); });
            Add("tcp.ack_raw", FT.Uint, delegate(Packet p, List<object> v) { if (Tcp(p)) v.Add((long)U.L(p.Data, p.L4Off + 8)); });
            Add("tcp.hdr_len", FT.Uint, delegate(Packet p, List<object> v) { if (Tcp(p)) v.Add((long)((p.Data[p.L4Off + 12] >> 4) * 4)); });
            Add("tcp.flags", FT.Uint, delegate(Packet p, List<object> v) { if (Tcp(p)) v.Add((long)TcpFlags(p)); });
            TcpFlag("fin", 0x01); TcpFlag("syn", 0x02); TcpFlag("reset", 0x04); TcpFlag("push", 0x08); TcpFlag("ack", 0x10);
            TcpFlag("urg", 0x20); TcpFlag("ece", 0x40); TcpFlag("cwr", 0x80); TcpFlag("ae", 0x100);
            Add("tcp.window_size_value", FT.Uint, delegate(Packet p, List<object> v) { if (Tcp(p)) v.Add((long)U.W(p.Data, p.L4Off + 14)); });
            Add("tcp.window_size", FT.Uint, delegate(Packet p, List<object> v)
            {
                if (Tcp(p)) { long w = U.W(p.Data, p.L4Off + 14); v.Add(p.WinScale >= 0 ? (w << p.WinScale) : w); }
            });
            Add("tcp.window_size_scalefactor", FT.Uint, delegate(Packet p, List<object> v) { if (Tcp(p)) v.Add(p.WinScale >= 0 ? (1L << p.WinScale) : -1L); });
            Add("tcp.checksum", FT.Uint, delegate(Packet p, List<object> v) { if (Tcp(p)) v.Add((long)U.W(p.Data, p.L4Off + 16)); });
            Add("tcp.urgent_pointer", FT.Uint, delegate(Packet p, List<object> v) { if (Tcp(p)) v.Add((long)U.W(p.Data, p.L4Off + 18)); });
            Add("tcp.payload", FT.Bytes, delegate(Packet p, List<object> v)
            {
                if (Tcp(p) && p.PayEnd > p.PayOff && p.PayEnd <= p.Data.Length) { byte[] b = new byte[p.PayEnd - p.PayOff]; Array.Copy(p.Data, p.PayOff, b, 0, b.Length); v.Add(b); }
            });
            Add("tcp.options.mss", FT.Bool, delegate(Packet p, List<object> v) { int o; if (TcpOpt(p, 2, out o)) v.Add(1L); });
            Add("tcp.options.mss_val", FT.Uint, delegate(Packet p, List<object> v) { int o; if (TcpOpt(p, 2, out o) && Room(p, o, 4)) v.Add((long)U.W(p.Data, o + 2)); });
            Add("tcp.options.wscale", FT.Bool, delegate(Packet p, List<object> v) { int o; if (TcpOpt(p, 3, out o)) v.Add(1L); });
            Add("tcp.options.wscale.shift", FT.Uint, delegate(Packet p, List<object> v) { int o; if (TcpOpt(p, 3, out o) && Room(p, o, 3)) v.Add((long)p.Data[o + 2]); });
            Add("tcp.options.wscale.multiplier", FT.Uint, delegate(Packet p, List<object> v) { int o; if (TcpOpt(p, 3, out o) && Room(p, o, 3)) v.Add(1L << p.Data[o + 2]); });
            Add("tcp.options.sack_perm", FT.Bool, delegate(Packet p, List<object> v) { int o; if (TcpOpt(p, 4, out o)) v.Add(1L); });
            Add("tcp.options.sack", FT.Bool, delegate(Packet p, List<object> v) { int o; if (TcpOpt(p, 5, out o)) v.Add(1L); });
            Add("tcp.options.timestamp", FT.Bool, delegate(Packet p, List<object> v) { int o; if (TcpOpt(p, 8, out o)) v.Add(1L); });
            Add("tcp.options.timestamp.tsval", FT.Uint, delegate(Packet p, List<object> v) { int o; if (TcpOpt(p, 8, out o) && Room(p, o, 10)) v.Add((long)U.L(p.Data, o + 2)); });
            Add("tcp.options.timestamp.tsecr", FT.Uint, delegate(Packet p, List<object> v) { int o; if (TcpOpt(p, 8, out o) && Room(p, o, 10)) v.Add((long)U.L(p.Data, o + 6)); });
            Add("tcp.reassembled_in", FT.Uint, delegate(Packet p, List<object> v) { if (Tcp(p) && p.ReasmIn > 0) v.Add((long)p.ReasmIn); });
            Add("tcp.reassembled.length", FT.Uint, delegate(Packet p, List<object> v) { if (Tcp(p) && p.ReasmData != null) v.Add((long)p.ReasmPduLen); });
            Add("tcp.segments", FT.Bool, delegate(Packet p, List<object> v) { if (Tcp(p) && p.ReasmData != null) v.Add(1L); });
            Add("tcp.analysis.flags", FT.Bool, delegate(Packet p, List<object> v) { if (Tcp(p) && p.TcpNote != null && p.TcpNote != "TCP Keep-Alive" && p.TcpNote != "TCP Keep-Alive ACK") v.Add(1L); });
            Add("tcp.analysis.keep_alive", FT.Bool, delegate(Packet p, List<object> v) { if (Tcp(p) && p.TcpNote == "TCP Keep-Alive") v.Add(1L); });
            Add("tcp.analysis.keep_alive_ack", FT.Bool, delegate(Packet p, List<object> v) { if (Tcp(p) && p.TcpNote == "TCP Keep-Alive ACK") v.Add(1L); });
            Add("tcp.analysis.retransmission", FT.Bool, delegate(Packet p, List<object> v) { if (Tcp(p) && p.TcpNote == "TCP Retransmission") v.Add(1L); });

            // ---- UDP
            Add("udp.srcport", FT.Uint, delegate(Packet p, List<object> v) { if (Udp(p)) v.Add((long)U.W(p.Data, p.L4Off)); });
            Add("udp.dstport", FT.Uint, delegate(Packet p, List<object> v) { if (Udp(p)) v.Add((long)U.W(p.Data, p.L4Off + 2)); });
            Add("udp.port", FT.Uint, delegate(Packet p, List<object> v) { if (Udp(p)) { v.Add((long)U.W(p.Data, p.L4Off)); v.Add((long)U.W(p.Data, p.L4Off + 2)); } });
            Add("udp.length", FT.Uint, delegate(Packet p, List<object> v) { if (Udp(p)) v.Add((long)U.W(p.Data, p.L4Off + 4)); });
            Add("udp.checksum", FT.Uint, delegate(Packet p, List<object> v) { if (Udp(p)) v.Add((long)U.W(p.Data, p.L4Off + 6)); });
            Add("udp.payload", FT.Bytes, delegate(Packet p, List<object> v)
            {
                if (Udp(p) && p.PayEnd > p.PayOff && p.PayEnd <= p.Data.Length) { byte[] b = new byte[p.PayEnd - p.PayOff]; Array.Copy(p.Data, p.PayOff, b, 0, b.Length); v.Add(b); }
            });

            // ---- application layers (recorded by the dissector)
            App("dns.id", FT.Uint);
            App("dns.flags.response", FT.Bool); App("dns.flags.opcode", FT.Uint); App("dns.flags.authoritative", FT.Bool);
            App("dns.flags.truncated", FT.Bool); App("dns.flags.recdesired", FT.Bool); App("dns.flags.recavail", FT.Bool); App("dns.flags.rcode", FT.Uint);
            App("dns.count.queries", FT.Uint); App("dns.count.answers", FT.Uint); App("dns.count.auth_rr", FT.Uint); App("dns.count.add_rr", FT.Uint);
            App("dns.qry.name", FT.Str); App("dns.qry.type", FT.Uint); App("dns.qry.class", FT.Uint);
            App("dns.resp.name", FT.Str); App("dns.resp.type", FT.Uint); App("dns.resp.class", FT.Uint); App("dns.resp.ttl", FT.Uint);
            App("dns.a", FT.Ipv4); App("dns.aaaa", FT.Ipv6); App("dns.cname", FT.Str); App("dns.ns", FT.Str);
            App("dns.ptr.domain_name", FT.Str); App("dns.mx.mail_exchange", FT.Str);
            App("dhcp.type", FT.Uint); App("dhcp.option.dhcp", FT.Uint); App("dhcp.id", FT.Uint); App("dhcp.hw.mac_addr", FT.Mac);
            App("dhcp.ip.client", FT.Ipv4); App("dhcp.ip.your", FT.Ipv4); App("dhcp.ip.server", FT.Ipv4); App("dhcp.ip.relay", FT.Ipv4);
            App("dhcp.option.requested_ip_address", FT.Ipv4); App("dhcp.option.hostname", FT.Str); App("dhcp.option.dhcp_server_id", FT.Ipv4);
            App("http.request", FT.Bool); App("http.response", FT.Bool);
            App("http.request.method", FT.Str); App("http.request.uri", FT.Str); App("http.request.version", FT.Str);
            App("http.response.code", FT.Uint); App("http.response.phrase", FT.Str); App("http.response.version", FT.Str);
            App("http.host", FT.Str); App("http.user_agent", FT.Str); App("http.content_type", FT.Str); App("http.content_length", FT.Uint);
            App("tls.record.content_type", FT.Uint); App("tls.record.opaque_type", FT.Uint); App("tls.record.version", FT.Uint);
            App("tls.handshake.type", FT.Uint); App("tls.handshake.extensions_server_name", FT.Str);

            // value ranges, so that e.g. "tcp.port == 99999" is reported instead of silently matching nothing
            foreach (string n in new string[] { "tcp.port", "tcp.srcport", "tcp.dstport", "udp.port", "udp.srcport", "udp.dstport", "arp.opcode", "arp.hw.type",
                "arp.proto.type", "eth.type", "eth.len", "tcp.window_size_value", "udp.length", "udp.checksum", "tcp.checksum", "ip.len", "ip.id", "ip.checksum",
                "ipv6.plen", "tcp.urgent_pointer", "dns.id", "tls.record.version" }) Map[n].Max = 65535;
            foreach (string n in new string[] { "ip.ttl", "ip.proto", "ip.dsfield", "icmp.type", "icmp.code", "icmpv6.type", "icmpv6.code", "ipv6.hlim", "ipv6.nxt", "ipv6.tclass",
                "igmp.type", "arp.hw.size", "arp.proto.size", "dhcp.type", "dhcp.option.dhcp", "tls.record.content_type", "tls.record.opaque_type", "tls.handshake.type", "dns.flags.opcode" }) Map[n].Max = 255;
            Map["vlan.id"].Max = 4095; Map["vlan.priority"].Max = 7; Map["ip.version"].Max = 15; Map["ipv6.version"].Max = 15; Map["ip.hdr_len"].Max = 60;
            Map["ip.flags"].Max = 7; Map["ip.dsfield.dscp"].Max = 63; Map["ip.dsfield.ecn"].Max = 3; Map["tcp.flags"].Max = 4095; Map["dns.flags.rcode"].Max = 15;
            Map["ipv6.flow"].Max = 0xFFFFF; Map["ip.frag_offset"].Max = 65528;
        }
    }

    // ---- the filter compiler
    // Grammar:  or := xor (('||'|'or') xor)* ; xor := and (('^^'|'xor') and)* ; and := not (('&&'|'and') not)*
    //           not := ('!'|'not') not | '(' or ')' | test
    //           test := operand [ op value | 'in' '{' set '}' ]      operand := field ['[' slice ']'] ['&' mask] | protocol '[' slice ']'
    public static class PacketFilter
    {
        enum T { Word, Str, Op, LP, RP, LB, RB, Comma, Slice, BitAnd, And, Or, Xor, Not, End }
        class Tok { public T Type; public string Text; public int Pos; }
        class P { public List<Tok> L; public int I; public Tok Cur { get { return L[I]; } } }

        class Operand
        {
            public FT Type; public string Name; public bool Masked; public long Max = long.MaxValue;
            public Action<Packet, List<object>> Get;
        }
        class Lit
        {
            public object V, Hi; public bool Range, Cidr, HasNum; public long Mask, Num; public byte[] Mask6;
            public System.Text.RegularExpressions.Regex Rx;
        }

        static readonly string[] Protocols = { "eth", "ethertype", "vlan", "llc", "stp", "wlan", "ip", "ipv6", "arp", "icmp", "icmpv6", "igmp",
            "tcp", "udp", "dns", "mdns", "llmnr", "dhcp", "ssdp", "ntp", "http", "tls", "ssl", "frame" };
        static readonly string[] SliceProtos = { "frame", "eth", "ip", "ipv6", "tcp", "udp", "icmp", "icmpv6", "arp" };

        // Returns null when the expression is valid (or empty), otherwise a message saying what is wrong.
        public static string Check(string expr)
        {
            try { Parse(expr); return null; }
            catch (FilterSyntaxException ex) { return ex.Message; }
        }

        public static Predicate<Packet> Compile(string expr)
        {
            if (expr == null || expr.Trim().Length == 0) return null;
            return Parse(expr);
        }

        public static int FieldCount { get { return Fields.Map.Count; } }

        static bool In(string[] list, string w) { return Array.IndexOf(list, w) >= 0; }
        static Tok Mk(T t, string text, int pos) { Tok k = new Tok(); k.Type = t; k.Text = text; k.Pos = pos; return k; }

        static string TypeName(FT t)
        {
            switch (t)
            {
                case FT.Uint: return "unsigned integer"; case FT.Bool: return "boolean"; case FT.Ipv4: return "IPv4 address";
                case FT.Ipv6: return "IPv6 address"; case FT.Mac: return "Ethernet address"; case FT.Str: return "string";
                case FT.Bytes: return "byte sequence"; default: return "number";
            }
        }

        // ---- "did you mean" suggestions
        static int Dist(string a, string b)
        {
            int[,] d = new int[a.Length + 1, b.Length + 1];
            for (int i = 0; i <= a.Length; i++) d[i, 0] = i;
            for (int j = 0; j <= b.Length; j++) d[0, j] = j;
            for (int i = 1; i <= a.Length; i++)
                for (int j = 1; j <= b.Length; j++)
                    d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + (a[i - 1] == b[j - 1] ? 0 : 1));
            return d[a.Length, b.Length];
        }
        static string Suggest(string w)
        {
            List<KeyValuePair<int, string>> c = new List<KeyValuePair<int, string>>();
            List<string> all = new List<string>(Fields.Map.Keys); all.AddRange(Protocols);
            foreach (string n in all)
            {
                int d = Dist(w, n);
                if (n.StartsWith(w) && w.Length >= 2) d = Math.Min(d, 1);
                if (d <= Math.Max(2, w.Length / 3)) c.Add(new KeyValuePair<int, string>(d, n));
            }
            c.Sort(delegate(KeyValuePair<int, string> x, KeyValuePair<int, string> y) { int r = x.Key.CompareTo(y.Key); return r != 0 ? r : string.CompareOrdinal(x.Value, y.Value); });
            List<string> top = new List<string>();
            foreach (KeyValuePair<int, string> k in c) { if (!top.Contains(k.Value)) top.Add(k.Value); if (top.Count == 3) break; }
            return string.Join(", ", top.ToArray());
        }

        // ---- lexer
        static List<Tok> Lex(string s)
        {
            List<Tok> r = new List<Tok>();
            int i = 0;
            while (i < s.Length)
            {
                char c = s[i];
                if (char.IsWhiteSpace(c)) { i++; continue; }
                int start = i;
                if (c == '(') { r.Add(Mk(T.LP, "(", i)); i++; }
                else if (c == ')') { r.Add(Mk(T.RP, ")", i)); i++; }
                else if (c == '{') { r.Add(Mk(T.LB, "{", i)); i++; }
                else if (c == '}') { r.Add(Mk(T.RB, "}", i)); i++; }
                else if (c == ',') { r.Add(Mk(T.Comma, ",", i)); i++; }
                else if (c == '[')
                {
                    int j = s.IndexOf(']', i + 1);
                    if (j < 0) throw new FilterSyntaxException("Missing closing ']' for the slice", i);
                    r.Add(Mk(T.Slice, s.Substring(i + 1, j - i - 1).Trim(), i)); i = j + 1;
                }
                else if (c == '"')
                {
                    int j = i + 1; StringBuilder sb = new StringBuilder();
                    while (j < s.Length && s[j] != '"')
                    {
                        if (s[j] == '\\' && j + 1 < s.Length) { j++; char e = s[j]; sb.Append(e == 'n' ? '\n' : e == 'r' ? '\r' : e == 't' ? '\t' : e); }
                        else sb.Append(s[j]);
                        j++;
                    }
                    if (j >= s.Length) throw new FilterSyntaxException("Missing closing quote (\")", i);
                    r.Add(Mk(T.Str, sb.ToString(), i)); i = j + 1;
                }
                else if (c == '&')
                {
                    if (i + 1 < s.Length && s[i + 1] == '&') { r.Add(Mk(T.And, "&&", i)); i += 2; }
                    else { r.Add(Mk(T.BitAnd, "&", i)); i++; }
                }
                else if (c == '|')
                {
                    if (i + 1 < s.Length && s[i + 1] == '|') { r.Add(Mk(T.Or, "||", i)); i += 2; }
                    else throw new FilterSyntaxException("Use || (or the word 'or') to combine alternatives", i);
                }
                else if (c == '^')
                {
                    if (i + 1 < s.Length && s[i + 1] == '^') { r.Add(Mk(T.Xor, "^^", i)); i += 2; }
                    else throw new FilterSyntaxException("Use ^^ (or the word 'xor') for exclusive-or", i);
                }
                else if (c == '~') { r.Add(Mk(T.Op, "matches", i)); i++; }
                else if (c == '!')
                {
                    if (i + 2 < s.Length && s[i + 1] == '=' && s[i + 2] == '=') { r.Add(Mk(T.Op, "!==", i)); i += 3; }
                    else if (i + 1 < s.Length && s[i + 1] == '=') { r.Add(Mk(T.Op, "!=", i)); i += 2; }
                    else { r.Add(Mk(T.Not, "!", i)); i++; }
                }
                else if (c == '=')
                {
                    if (i + 2 < s.Length && s[i + 1] == '=' && s[i + 2] == '=') { r.Add(Mk(T.Op, "===", i)); i += 3; }
                    else if (i + 1 < s.Length && s[i + 1] == '=') { r.Add(Mk(T.Op, "==", i)); i += 2; }
                    else throw new FilterSyntaxException("Use == to compare (a single = is not valid)", i);
                }
                else if (c == '<' || c == '>')
                {
                    if (i + 1 < s.Length && s[i + 1] == '=') { r.Add(Mk(T.Op, c.ToString() + "=", i)); i += 2; }
                    else { r.Add(Mk(T.Op, c.ToString(), i)); i++; }
                }
                else
                {
                    int j = i;
                    while (j < s.Length && !char.IsWhiteSpace(s[j]) && "()[]{},\"&|^~!=<>".IndexOf(s[j]) < 0) j++;
                    string w = s.Substring(i, j - i);
                    string lw = w.ToLowerInvariant();
                    switch (lw)
                    {
                        case "and": r.Add(Mk(T.And, w, start)); break;
                        case "or": r.Add(Mk(T.Or, w, start)); break;
                        case "xor": r.Add(Mk(T.Xor, w, start)); break;
                        case "not": r.Add(Mk(T.Not, w, start)); break;
                        case "eq": case "any_eq": r.Add(Mk(T.Op, "==", start)); break;
                        case "all_eq": r.Add(Mk(T.Op, "===", start)); break;
                        case "all_ne": r.Add(Mk(T.Op, "!=", start)); break;
                        case "any_ne": r.Add(Mk(T.Op, "!==", start)); break;
                        case "ne": r.Add(Mk(T.Op, "!=", start)); break;
                        case "gt": r.Add(Mk(T.Op, ">", start)); break;
                        case "lt": r.Add(Mk(T.Op, "<", start)); break;
                        case "ge": r.Add(Mk(T.Op, ">=", start)); break;
                        case "le": r.Add(Mk(T.Op, "<=", start)); break;
                        case "contains": r.Add(Mk(T.Op, "contains", start)); break;
                        case "matches": r.Add(Mk(T.Op, "matches", start)); break;
                        case "in": r.Add(Mk(T.Op, "in", start)); break;
                        default: r.Add(Mk(T.Word, w, start)); break;
                    }
                    i = j;
                }
            }
            r.Add(Mk(T.End, "", s.Length));
            return r;
        }

        // ---- parser
        static Predicate<Packet> Parse(string expr)
        {
            if (expr == null || expr.Trim().Length == 0) return null;
            P p = new P(); p.L = Lex(expr); p.I = 0;
            Predicate<Packet> r = Or(p);
            if (p.Cur.Type != T.End)
            {
                if (p.Cur.Type == T.RP) throw new FilterSyntaxException("Unexpected ')' - there is no matching '('", p.Cur.Pos);
                throw new FilterSyntaxException("Unexpected '" + p.Cur.Text + "' - expected &&, ||, or the end of the filter", p.Cur.Pos);
            }
            return r;
        }

        static Predicate<Packet> Or(P p)
        {
            List<Predicate<Packet>> parts = new List<Predicate<Packet>>();
            parts.Add(Xor(p));
            while (p.Cur.Type == T.Or) { p.I++; parts.Add(Xor(p)); }
            if (parts.Count == 1) return parts[0];
            return delegate(Packet k) { for (int i = 0; i < parts.Count; i++) if (parts[i](k)) return true; return false; };
        }

        static Predicate<Packet> Xor(P p)
        {
            List<Predicate<Packet>> parts = new List<Predicate<Packet>>();
            parts.Add(And(p));
            while (p.Cur.Type == T.Xor) { p.I++; parts.Add(And(p)); }
            if (parts.Count == 1) return parts[0];
            return delegate(Packet k) { bool r = false; for (int i = 0; i < parts.Count; i++) r ^= parts[i](k); return r; };
        }

        static Predicate<Packet> And(P p)
        {
            List<Predicate<Packet>> parts = new List<Predicate<Packet>>();
            parts.Add(Not(p));
            while (p.Cur.Type == T.And) { p.I++; parts.Add(Not(p)); }
            if (parts.Count == 1) return parts[0];
            return delegate(Packet k) { for (int i = 0; i < parts.Count; i++) if (!parts[i](k)) return false; return true; };
        }

        static Predicate<Packet> Not(P p)
        {
            if (p.Cur.Type == T.Not)
            {
                p.I++;
                Predicate<Packet> inner = Not(p);
                return delegate(Packet k) { return !inner(k); };
            }
            if (p.Cur.Type == T.LP)
            {
                int open = p.Cur.Pos;
                p.I++;
                if (p.Cur.Type == T.RP) throw new FilterSyntaxException("Empty parentheses - put a condition inside ( )", open);
                Predicate<Packet> inner = Or(p);
                if (p.Cur.Type != T.RP) throw new FilterSyntaxException("Missing ')' to close the '(' opened here", open);
                p.I++;
                return inner;
            }
            return Test(p);
        }

        // ---- operands
        static Operand FieldOperand(P p, Tok t, string w)
        {
            FieldDef f;
            if (Fields.Map.TryGetValue(w, out f))
            {
                Operand o = new Operand(); o.Type = f.Type; o.Name = t.Text; o.Get = f.Get; o.Max = f.Max;
                return o;
            }
            return null;
        }

        static Operand ApplySlice(Operand o, Tok slice)
        {
            if (o.Type == FT.Uint || o.Type == FT.Bool || o.Type == FT.Float)
                throw new FilterSyntaxException("A slice [...] cannot be applied to '" + o.Name + "' (" + TypeName(o.Type) + " field); use it on addresses, strings or byte fields", slice.Pos);
            int a, b; bool toEnd; ParseSlice(slice, out a, out b, out toEnd);
            Action<Packet, List<object>> src = o.Get; FT st = o.Type;
            Operand r = new Operand(); r.Type = FT.Bytes; r.Name = o.Name;
            r.Get = delegate(Packet pk, List<object> outv)
            {
                List<object> tmp = new List<object>(2); src(pk, tmp);
                for (int i = 0; i < tmp.Count; i++)
                {
                    byte[] bytes = ToBytes(st, tmp[i]);
                    byte[] sl = Slice(bytes, a, b, toEnd);
                    if (sl != null) outv.Add(sl);
                }
            };
            return r;
        }

        static void ParseSlice(Tok slice, out int start, out int len, out bool toEnd)
        {
            string s = slice.Text; start = 0; len = 1; toEnd = false;
            if (s.Length == 0) throw new FilterSyntaxException("Empty slice [] - use [offset], [offset:length] or [from-to]", slice.Pos);
            int colon = s.IndexOf(':');
            int dash = s.IndexOf('-', 1);
            try
            {
                if (colon >= 0)
                {
                    string a = s.Substring(0, colon).Trim(), b = s.Substring(colon + 1).Trim();
                    start = a.Length == 0 ? 0 : int.Parse(a);
                    if (b.Length == 0) toEnd = true; else len = int.Parse(b);
                }
                else if (dash > 0)
                {
                    int from = int.Parse(s.Substring(0, dash).Trim()), to = int.Parse(s.Substring(dash + 1).Trim());
                    if (to < from) throw new FilterSyntaxException("Slice range [" + s + "] ends before it starts", slice.Pos);
                    start = from; len = to - from + 1;
                }
                else start = int.Parse(s);
            }
            catch (FormatException) { throw new FilterSyntaxException("'[" + s + "]' is not a valid slice - use [offset], [offset:length], [:length], [offset:] or [from-to]", slice.Pos); }
            if (!toEnd && len <= 0) throw new FilterSyntaxException("A slice length must be at least 1", slice.Pos);
        }

        static byte[] Slice(byte[] b, int start, int len, bool toEnd)
        {
            if (start < 0) start = b.Length + start;
            if (start < 0 || start >= b.Length) return null;
            int n = toEnd ? b.Length - start : len;
            if (start + n > b.Length) return null;
            byte[] r = new byte[n];
            Array.Copy(b, start, r, 0, n);
            return r;
        }

        static byte[] ToBytes(FT t, object v)
        {
            switch (t)
            {
                case FT.Ipv4: { long x = (long)v; return new byte[] { (byte)(x >> 24), (byte)(x >> 16), (byte)(x >> 8), (byte)x }; }
                case FT.Mac: { long x = (long)v; return new byte[] { (byte)(x >> 40), (byte)(x >> 32), (byte)(x >> 24), (byte)(x >> 16), (byte)(x >> 8), (byte)x }; }
                case FT.Str: return Encoding.UTF8.GetBytes((string)v);
                default: return (byte[])v;     // Ipv6, Bytes
            }
        }

        static long BytesToNum(byte[] b)
        {
            long n = 0;
            for (int i = 0; i < b.Length; i++) n = (n << 8) | b[i];
            return n;
        }

        // primary operand: FIELD [slice] [& mask]  |  PROTOCOL slice [& mask]
        static Operand ParseOperand(P p, out bool isBareProtocol, out string protoName)
        {
            isBareProtocol = false; protoName = null;
            Tok t = p.Cur;
            string w = t.Text.ToLowerInvariant();
            Operand o = FieldOperand(p, t, w);
            if (o == null && In(SliceProtos, w) && p.L[p.I + 1].Type == T.Slice)
            {
                Operand po = new Operand(); po.Type = FT.Bytes; po.Name = t.Text;
                string layer = w; Tok st = p.L[p.I + 1];
                int a, b; bool toEnd; ParseSlice(st, out a, out b, out toEnd);
                po.Get = delegate(Packet pk, List<object> outv)
                {
                    int off, end;
                    if (!Fields.LayerRange(layer, pk, out off, out end) || end > pk.Data.Length || end < off) return;
                    byte[] layerBytes = new byte[end - off];
                    Array.Copy(pk.Data, off, layerBytes, 0, layerBytes.Length);
                    byte[] sl = Slice(layerBytes, a, b, toEnd);
                    if (sl != null) outv.Add(sl);
                };
                p.I += 2;
                return MaybeMask(p, po);
            }
            if (o == null)
            {
                if (In(Protocols, w)) { isBareProtocol = true; protoName = w; p.I++; return null; }
                string sug = Suggest(w);
                if (System.Net.IPAddress.TryParse(t.Text, out addrProbe))
                    throw new FilterSyntaxException("'" + t.Text + "' on its own is not a condition - did you mean ip.addr == " + t.Text + " ?", t.Pos);
                throw new FilterSyntaxException("Unknown protocol or field '" + t.Text + "'." + (sug.Length > 0 ? " Did you mean: " + sug + "?" : "") +
                    " (" + Fields.Map.Count + " fields are supported, e.g. ip.addr, tcp.port, udp.port, dns.qry.name, http.request.method, tls.handshake.type)", t.Pos);
            }
            p.I++;
            if (p.Cur.Type == T.Slice) { Tok s = p.Cur; p.I++; o = ApplySlice(o, s); }
            return MaybeMask(p, o);
        }
        [ThreadStatic] static System.Net.IPAddress addrProbe;

        static Operand MaybeMask(P p, Operand o)
        {
            if (p.Cur.Type != T.BitAnd) return o;
            Tok amp = p.Cur; p.I++;
            Tok m = p.Cur;
            if (m.Type != T.Word) throw new FilterSyntaxException("Missing number after '&'", amp.Pos);
            long mask;
            if (!ParseNumber(m.Text, out mask)) throw new FilterSyntaxException("'" + m.Text + "' is not a valid number for the & mask", m.Pos);
            p.I++;
            Action<Packet, List<object>> src = o.Get; FT st = o.Type;
            if (st == FT.Bytes)
            {
                Operand r = new Operand(); r.Type = FT.Uint; r.Name = o.Name; r.Masked = true;
                r.Get = delegate(Packet pk, List<object> outv)
                {
                    List<object> tmp = new List<object>(2); src(pk, tmp);
                    for (int i = 0; i < tmp.Count; i++) { byte[] b = (byte[])tmp[i]; if (b.Length >= 1 && b.Length <= 8) outv.Add(BytesToNum(b) & mask); }
                };
                return r;
            }
            if (st != FT.Uint && st != FT.Bool) throw new FilterSyntaxException("The & operator needs a numeric field or a byte slice, but '" + o.Name + "' has type " + TypeName(st), amp.Pos);
            Operand r2 = new Operand(); r2.Type = FT.Uint; r2.Name = o.Name; r2.Masked = true;
            r2.Get = delegate(Packet pk, List<object> outv)
            {
                List<object> tmp = new List<object>(2); src(pk, tmp);
                for (int i = 0; i < tmp.Count; i++) outv.Add(((long)tmp[i]) & mask);
            };
            return r2;
        }

        static bool ParseNumber(string s, out long n)
        {
            n = 0;
            if (s.Length > 2 && (s.StartsWith("0x") || s.StartsWith("0X"))) return long.TryParse(s.Substring(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out n);
            return long.TryParse(s, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out n);
        }

        // ---- a single test
        static Predicate<Packet> Test(P p)
        {
            Tok first = p.Cur;
            if (first.Type == T.End)
            {
                Tok prev = p.I > 0 ? p.L[p.I - 1] : null;
                if (prev != null && (prev.Type == T.And || prev.Type == T.Or || prev.Type == T.Xor || prev.Type == T.Not))
                    throw new FilterSyntaxException("Missing condition after '" + prev.Text + "'", first.Pos);
                throw new FilterSyntaxException("The filter ends too early - a condition is missing", first.Pos);
            }
            if (first.Type != T.Word)
            {
                if (first.Type == T.And || first.Type == T.Or || first.Type == T.Xor) throw new FilterSyntaxException("Missing condition before '" + first.Text + "'", first.Pos);
                if (first.Type == T.RP) throw new FilterSyntaxException("Unexpected ')' - there is no matching '('", first.Pos);
                if (first.Type == T.Op) throw new FilterSyntaxException("Missing field name before '" + first.Text + "'", first.Pos);
                throw new FilterSyntaxException("Expected a protocol or field name, found '" + first.Text + "'", first.Pos);
            }
            string quant = null;
            string fw = first.Text.ToLowerInvariant();
            if ((fw == "all" || fw == "any") && p.L[p.I + 1].Type == T.Word && !Fields.Map.ContainsKey(fw)) { quant = fw; p.I++; first = p.Cur; }
            bool bare; string proto;
            Operand L = ParseOperand(p, out bare, out proto);
            if (bare)
            {
                if (p.Cur.Type == T.Op)
                    throw new FilterSyntaxException("'" + first.Text + "' is a protocol, not a field - use a field such as " + first.Text + ".xxx, or just '" + first.Text + "' on its own", first.Pos);
                string kw = proto == "ssl" ? "tls" : proto;
                if (kw == "frame") return delegate(Packet k) { return true; };
                return delegate(Packet k)
                {
                    return (":" + k.Chain + ":").IndexOf(":" + kw + ":") >= 0 || string.Equals(k.Protocol, kw, StringComparison.OrdinalIgnoreCase);
                };
            }
            if (p.Cur.Type != T.Op)
            {
                // no operator: boolean field / non-zero masked value / field exists
                List<object> buf0 = new List<object>(4);
                Operand LL = L;
                if (LL.Type == FT.Bool || LL.Masked)
                    return delegate(Packet k) { buf0.Clear(); LL.Get(k, buf0); for (int i = 0; i < buf0.Count; i++) if ((long)buf0[i] != 0) return true; return false; };
                return delegate(Packet k) { buf0.Clear(); LL.Get(k, buf0); return buf0.Count > 0; };
            }
            Tok op = p.Cur; p.I++;
            if (op.Text == "in") return InTest(p, L, first, op);
            string baseOp = op.Text; bool allQ = false, negQ = false;
            if (op.Text == "!=") { allQ = true; negQ = true; baseOp = "=="; }
            else if (op.Text == "===") { allQ = true; baseOp = "=="; }
            else if (op.Text == "!==") { negQ = true; baseOp = "=="; }
            if (quant != null) allQ = quant == "all";

            // legal operators for the field type
            bool textOp = op.Text == "contains" || op.Text == "matches";
            bool order = op.Text == ">" || op.Text == "<" || op.Text == ">=" || op.Text == "<=";
            if (L.Type == FT.Bool && (textOp || order)) throw new FilterSyntaxException("Operator '" + op.Text + "' cannot be used with '" + L.Name + "' (a boolean) - use == or !=", op.Pos);
            if ((L.Type == FT.Ipv6 || L.Type == FT.Mac) && (textOp || order)) throw new FilterSyntaxException("Operator '" + op.Text + "' cannot be used with '" + L.Name + "' (" + TypeName(L.Type) + ") - use == or !=", op.Pos);
            if ((L.Type == FT.Uint || L.Type == FT.Ipv4 || L.Type == FT.Float) && textOp) throw new FilterSyntaxException("Operator '" + op.Text + "' cannot be used with '" + L.Name + "' (" + TypeName(L.Type) + ") - use == != > < >= <= or 'in'", op.Pos);
            if (L.Type == FT.Bytes && order) throw new FilterSyntaxException("Operator '" + op.Text + "' cannot be used with '" + L.Name + "' (a byte sequence) - use ==, !=, contains, matches or 'in'", op.Pos);

            Tok v = p.Cur;
            if (v.Type != T.Word && v.Type != T.Str) throw new FilterSyntaxException("Missing value after '" + op.Text + "'", v.Type == T.End ? op.Pos : v.Pos);
            p.I++;

            // right-hand side may be another field
            string vw = v.Text.ToLowerInvariant();
            Operand R = null;
            if (v.Type == T.Word && Fields.Map.ContainsKey(vw) && !textOp)
            {
                R = FieldOperand(p, v, vw);
                if (R.Type != L.Type) throw new FilterSyntaxException("Cannot compare '" + L.Name + "' (" + TypeName(L.Type) + ") with '" + v.Text + "' (" + TypeName(R.Type) + ")", v.Pos);
            }
            Lit lit = null;
            if (R == null) lit = ParseLit(L, v, op.Text == "matches");

            string o = baseOp;
            List<object> lb = new List<object>(4), rb = new List<object>(4);
            FT ty = L.Type;
            Operand LF = L, RF = R; Lit LT = lit;
            bool all = allQ, neg = negQ;
            return delegate(Packet k)
            {
                lb.Clear(); LF.Get(k, lb);
                if (lb.Count == 0) return false;              // the field must be present in the packet
                if (RF != null) { rb.Clear(); RF.Get(k, rb); }
                for (int i = 0; i < lb.Count; i++)
                {
                    bool m = Elem(ty, lb[i], RF != null ? rb : null, LT, o);
                    if (neg) m = !m;
                    if (all) { if (!m) return false; }
                    else if (m) return true;
                }
                return all;
            };
        }

        static bool Elem(FT ty, object l, List<object> rb, Lit lit, string o)
        {
            if (rb != null)
            {
                for (int j = 0; j < rb.Count; j++) if (Rel(o, CmpVals(ty, l, rb[j]))) return true;
                return false;
            }
            return LitTest(ty, l, lit, o);
        }

        static bool Rel(string o, int c)
        {
            switch (o)
            {
                case "==": return c == 0;
                case ">": return c > 0;
                case "<": return c < 0;
                case ">=": return c >= 0;
                case "<=": return c <= 0;
            }
            return false;
        }

        static int CmpVals(FT t, object a, object b)
        {
            switch (t)
            {
                case FT.Float: return Convert.ToDouble(a).CompareTo(Convert.ToDouble(b));
                case FT.Str: return string.CompareOrdinal((string)a, (string)b);
                case FT.Bytes:
                case FT.Ipv6:
                    {
                        byte[] x = (byte[])a, y = (byte[])b;
                        int n = Math.Min(x.Length, y.Length);
                        for (int i = 0; i < n; i++) if (x[i] != y[i]) return x[i].CompareTo(y[i]);
                        return x.Length.CompareTo(y.Length);
                    }
                default: return ((long)a).CompareTo((long)b);
            }
        }

        static bool LitTest(FT t, object l, Lit m, string o)
        {
            if (o == "contains")
            {
                if (t == FT.Str) return ((string)l).IndexOf((string)m.V, StringComparison.Ordinal) >= 0;
                return IndexOf((byte[])l, (byte[])m.V) >= 0;
            }
            if (o == "matches")
            {
                string s = t == FT.Str ? (string)l : Latin1((byte[])l);
                return m.Rx.IsMatch(s);
            }
            if (m.Range) return CmpLit(t, l, m.V, m) >= 0 && CmpLit(t, l, m.Hi, m) <= 0;
            if (m.Cidr)
            {
                if (t == FT.Ipv4) return (((long)l) & m.Mask) == (long)m.V;
                byte[] a = (byte[])l, n = (byte[])m.V;
                for (int i = 0; i < 16; i++) if ((a[i] & m.Mask6[i]) != n[i]) return false;
                return true;
            }
            return Rel(o, CmpLit(t, l, m.V, m));
        }

        static int CmpLit(FT t, object l, object v, Lit m)
        {
            if (t == FT.Bytes && m.HasNum)
            {
                byte[] b = (byte[])l;
                if (b.Length > 8) return 1;
                return BytesToNum(b).CompareTo((long)v);
            }
            return CmpVals(t, l, v);
        }

        static string Latin1(byte[] b) { char[] c = new char[b.Length]; for (int i = 0; i < b.Length; i++) c[i] = (char)b[i]; return new string(c); }

        static int IndexOf(byte[] hay, byte[] needle)
        {
            if (needle.Length == 0) return 0;
            for (int i = 0; i + needle.Length <= hay.Length; i++)
            {
                int j = 0;
                while (j < needle.Length && hay[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }

        // ---- literals
        static bool IsDottedQuad(string s)
        {
            string[] p = s.Split('.');
            if (p.Length != 4) return false;
            foreach (string x in p) { int n; if (x.Length == 0 || x.Length > 3 || !int.TryParse(x, out n) || n > 255) return false; }
            return true;
        }
        static long QuadToLong(string s)
        {
            string[] p = s.Split('.');
            return ((long)uint.Parse(p[0]) << 24) + ((long)uint.Parse(p[1]) << 16) + ((long)uint.Parse(p[2]) << 8) + (long)uint.Parse(p[3]);
        }
        static bool ParseMac(string s, out long v)
        {
            v = 0;
            string[] p = s.Split(new char[] { ':', '-', '.' });
            if (p.Length != 6) return false;
            foreach (string x in p)
            {
                int b;
                if (x.Length != 2 || !int.TryParse(x, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out b)) return false;
                v = (v << 8) + b;
            }
            return true;
        }
        static bool ParseHexBytes(string s, out byte[] b)
        {
            b = null;
            string[] p = s.Split(new char[] { ':', '-', '.' });
            if (p.Length < 1) return false;
            List<byte> l = new List<byte>();
            foreach (string x in p)
            {
                int n;
                if (x.Length != 2 || !int.TryParse(x, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out n)) return false;
                l.Add((byte)n);
            }
            b = l.ToArray();
            return true;
        }

        static Lit ParseLit(Operand L, Tok v, bool regex)
        {
            FT t = L.Type; string s = v.Text;
            Lit m = new Lit();
            string fld = "'" + L.Name + "'";
            if (regex)
            {
                if (t != FT.Str && t != FT.Bytes) throw new FilterSyntaxException("'matches' can only be used with string or byte fields, not " + fld, v.Pos);
                try { m.Rx = new System.Text.RegularExpressions.Regex(s, System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant); }
                catch (ArgumentException ex) { throw new FilterSyntaxException("Invalid regular expression: " + ex.Message, v.Pos); }
                return m;
            }
            switch (t)
            {
                case FT.Uint:
                    {
                        long n;
                        if (v.Type == T.Str || !ParseNumber(s, out n)) throw new FilterSyntaxException("'" + s + "' is not a valid number for " + fld + " (use decimal or 0x hex)", v.Pos);
                        if (n < 0) throw new FilterSyntaxException("'" + s + "' is negative - " + fld + " is unsigned", v.Pos);
                        if (n > L.Max) throw new FilterSyntaxException("'" + s + "' is too large for " + fld + " (maximum " + L.Max + ")", v.Pos);
                        m.V = n; return m;
                    }
                case FT.Float:
                    {
                        double d;
                        if (!double.TryParse(s, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out d)) throw new FilterSyntaxException("'" + s + "' is not a valid number for " + fld, v.Pos);
                        m.V = d; return m;
                    }
                case FT.Bool:
                    {
                        string ls = s.ToLowerInvariant();
                        if (ls == "true" || ls == "1") m.V = 1L; else if (ls == "false" || ls == "0") m.V = 0L;
                        else throw new FilterSyntaxException("'" + s + "' is not a valid boolean for " + fld + " (use true, false, 1 or 0)", v.Pos);
                        return m;
                    }
                case FT.Ipv4:
                    {
                        string addr = s; int prefix = -1;
                        int sl = s.IndexOf('/');
                        if (sl >= 0)
                        {
                            addr = s.Substring(0, sl);
                            if (!int.TryParse(s.Substring(sl + 1), out prefix) || prefix < 0 || prefix > 32) throw new FilterSyntaxException("'" + s.Substring(sl + 1) + "' is not a valid IPv4 prefix length (0-32)", v.Pos);
                        }
                        if (!IsDottedQuad(addr)) throw new FilterSyntaxException("'" + addr + "' is not a valid IPv4 address for " + fld + (System.Net.IPAddress.TryParse(addr, out addrProbe) && addr.Contains(":") ? " - use ipv6.addr for IPv6" : ""), v.Pos);
                        long ip = QuadToLong(addr);
                        if (prefix >= 0) { m.Cidr = true; m.Mask = prefix == 0 ? 0 : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL; m.V = ip & m.Mask; }
                        else m.V = ip;
                        return m;
                    }
                case FT.Ipv6:
                    {
                        string addr = s; int prefix = -1;
                        int sl = s.IndexOf('/');
                        if (sl >= 0)
                        {
                            addr = s.Substring(0, sl);
                            if (!int.TryParse(s.Substring(sl + 1), out prefix) || prefix < 0 || prefix > 128) throw new FilterSyntaxException("'" + s.Substring(sl + 1) + "' is not a valid IPv6 prefix length (0-128)", v.Pos);
                        }
                        System.Net.IPAddress ia;
                        if (!System.Net.IPAddress.TryParse(addr, out ia) || ia.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                            throw new FilterSyntaxException("'" + addr + "' is not a valid IPv6 address for " + fld + (IsDottedQuad(addr) ? " - use ip.addr for IPv4" : ""), v.Pos);
                        byte[] b = ia.GetAddressBytes();
                        if (prefix >= 0)
                        {
                            m.Cidr = true; m.Mask6 = new byte[16];
                            for (int i = 0; i < 16; i++) { int bits = Math.Max(0, Math.Min(8, prefix - i * 8)); m.Mask6[i] = (byte)(0xFF << (8 - bits)); b[i] = (byte)(b[i] & m.Mask6[i]); }
                        }
                        m.V = b; return m;
                    }
                case FT.Mac:
                    {
                        long mv;
                        if (!ParseMac(s, out mv)) throw new FilterSyntaxException("'" + s + "' is not a valid Ethernet address for " + fld + " (use aa:bb:cc:dd:ee:ff)", v.Pos);
                        m.V = mv; return m;
                    }
                case FT.Str:
                    m.V = s; return m;
                default:   // Bytes
                    {
                        if (v.Type == T.Str) { m.V = Encoding.UTF8.GetBytes(s); return m; }
                        byte[] hb; long n;
                        if (s.IndexOfAny(new char[] { ':', '-', '.' }) >= 0 && ParseHexBytes(s, out hb)) { m.V = hb; return m; }
                        if (ParseNumber(s, out n)) { m.HasNum = true; m.V = n; m.Num = n; return m; }
                        throw new FilterSyntaxException("'" + s + "' is not a valid byte value for " + fld + " - use aa:bb:cc, 0x1f, a number or \"text\"", v.Pos);
                    }
            }
        }

        // ---- membership: field in {1 2 80..90 10.0.0.0/8}
        static Predicate<Packet> InTest(P p, Operand L, Tok first, Tok op)
        {
            if (p.Cur.Type != T.LB) throw new FilterSyntaxException("'in' must be followed by a set in braces, e.g. in {80 443 8000..8080}", p.Cur.Pos);
            Tok open = p.Cur; p.I++;
            List<Lit> set = new List<Lit>();
            while (p.Cur.Type != T.RB)
            {
                if (p.Cur.Type == T.Comma) { p.I++; continue; }
                if (p.Cur.Type == T.End) throw new FilterSyntaxException("Missing '}' to close the set opened here", open.Pos);
                if (p.Cur.Type != T.Word && p.Cur.Type != T.Str) throw new FilterSyntaxException("Unexpected '" + p.Cur.Text + "' inside the set", p.Cur.Pos);
                Tok m = p.Cur; p.I++;
                int dd = m.Type == T.Word ? m.Text.IndexOf("..") : -1;
                if (dd > 0 && m.Text.Length > dd + 2)
                {
                    if (L.Type == FT.Str || L.Type == FT.Bool || L.Type == FT.Ipv6 || L.Type == FT.Mac || L.Type == FT.Bytes)
                        throw new FilterSyntaxException("Ranges (a..b) cannot be used with '" + L.Name + "' (" + TypeName(L.Type) + ")", m.Pos);
                    Lit lo = ParseLit(L, Mk(T.Word, m.Text.Substring(0, dd), m.Pos), false);
                    Lit hi = ParseLit(L, Mk(T.Word, m.Text.Substring(dd + 2), m.Pos), false);
                    lo.Hi = hi.V; lo.Range = true; set.Add(lo);
                }
                else set.Add(ParseLit(L, m, false));
            }
            p.I++;
            if (set.Count == 0) throw new FilterSyntaxException("The set after 'in' is empty", open.Pos);
            List<object> lb = new List<object>(4);
            FT ty = L.Type; Operand LF = L;
            return delegate(Packet k)
            {
                lb.Clear(); LF.Get(k, lb);
                for (int i = 0; i < lb.Count; i++)
                    for (int j = 0; j < set.Count; j++)
                        if (LitTest(ty, lb[i], set[j], "==")) return true;
                return false;
            };
        }
    }

    // ------------------------------------------------------------------ hex dump
    public static class HexDump
    {
        // Wireshark layout: offset, 2 spaces, 8 bytes, extra space, 8 bytes, 3 spaces, ASCII (gap after 8).
        public static List<HexSeg> Build(byte[] d, int hs, int hl)
        {
            List<HexSeg> segs = new List<HexSeg>();
            if (d == null) return segs;
            int he = hs + hl;
            for (int row = 0; row < d.Length; row += 16)
            {
                Add(segs, row.ToString("x4") + "  ", false);
                for (int i = 0; i < 16; i++)
                {
                    int idx = row + i;
                    bool hl2 = hl > 0 && idx >= hs && idx < he;
                    if (idx < d.Length) Add(segs, d[idx].ToString("x2"), hl2); else Add(segs, "  ", false);
                    bool nextHl = hl > 0 && idx + 1 >= hs && idx + 1 < he && i < 15 && idx + 1 < d.Length;
                    Add(segs, i == 7 ? "  " : " ", hl2 && nextHl);
                }
                Add(segs, "  ", false);
                for (int i = 0; i < 16; i++)
                {
                    int idx = row + i;
                    if (idx >= d.Length) break;
                    bool hl2 = hl > 0 && idx >= hs && idx < he;
                    byte b = d[idx];
                    Add(segs, (b >= 32 && b < 127) ? ((char)b).ToString() : ".", hl2);
                    if (i == 7 && idx + 1 < d.Length) Add(segs, " ", hl2 && (idx + 1) < he);
                }
                Add(segs, "\n", false);
            }
            return segs;
        }

        static void Add(List<HexSeg> l, string t, bool hl)
        {
            if (l.Count > 0 && l[l.Count - 1].Hl == hl) { l[l.Count - 1].Text += t; return; }
            HexSeg s = new HexSeg(); s.Text = t; s.Hl = hl; l.Add(s);
        }
    }

    // ------------------------------------------------------------------ pcap I/O
    public static class PcapIO
    {
        static readonly long EpochTicks = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).Ticks;

        static uint R32(byte[] b, int o, bool be)
        {
            if (be) return ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | b[o + 3];
            return ((uint)b[o + 3] << 24) | ((uint)b[o + 2] << 16) | ((uint)b[o + 1] << 8) | b[o];
        }
        static int R16(byte[] b, int o, bool be)
        {
            return be ? (b[o] << 8) | b[o + 1] : (b[o + 1] << 8) | b[o];
        }

        static bool ReadFull(Stream s, byte[] buf, int n)
        {
            int got = 0;
            while (got < n)
            {
                int r = s.Read(buf, got, n - got);
                if (r <= 0) return false;
                got += r;
            }
            return true;
        }

        static void Push(ConcurrentQueue<RawPacket> q, RawPacket r, SharedState st)
        {
            while (q.Count > 50000 && !st.Cancel) Thread.Sleep(5);
            q.Enqueue(r);
            st.Count++;
        }

        // Reads classic pcap (both endians, us/ns) and pcapng. Runs on a worker runspace.
        public static void Read(string path, ConcurrentQueue<RawPacket> q, SharedState st)
        {
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 16))
                {
                    st.Total = fs.Length;
                    byte[] magic = new byte[4];
                    if (!ReadFull(fs, magic, 4)) throw new InvalidDataException("File is empty.");
                    uint m = (uint)(magic[0] | (magic[1] << 8) | (magic[2] << 16) | (magic[3] << 24));
                    if (m == 0x0A0D0D0A) ReadPcapNg(fs, q, st);
                    else if (m == 0xA1B2C3D4 || m == 0xD4C3B2A1 || m == 0xA1B23C4D || m == 0x4D3CB2A1) ReadPcap(fs, m, q, st);
                    else throw new InvalidDataException("Not a pcap or pcapng file.");
                }
            }
            catch (Exception ex) { st.Error = ex.Message; }
            finally { st.Done = true; }
        }

        static void ReadPcap(FileStream fs, uint m, ConcurrentQueue<RawPacket> q, SharedState st)
        {
            bool be = (m == 0xD4C3B2A1 || m == 0x4D3CB2A1);
            bool nano = (m == 0xA1B23C4D || m == 0x4D3CB2A1);
            byte[] hdr = new byte[20];
            if (!ReadFull(fs, hdr, 20)) throw new InvalidDataException("Truncated pcap header.");
            int link = (int)R32(hdr, 16, be);
            byte[] rec = new byte[16];
            while (!st.Cancel && ReadFull(fs, rec, 16))
            {
                uint sec = R32(rec, 0, be), frac = R32(rec, 4, be), incl = R32(rec, 8, be), orig = R32(rec, 12, be);
                if (incl > 0x4000000) throw new InvalidDataException("Corrupt packet record.");
                byte[] data = new byte[incl];
                if (!ReadFull(fs, data, (int)incl)) break;
                RawPacket r = new RawPacket();
                r.Ticks = EpochTicks + (long)sec * 10000000L + (nano ? (long)frac / 100L : (long)frac * 10L);
                r.Data = data; r.OrigLen = (int)orig; r.LinkType = link;
                Push(q, r, st);
                st.Progress = fs.Position;
            }
        }

        class Iface { public int Link; public decimal UnitsPerSec = 1000000m; public string Name; public string Desc; }

        static void ReadPcapNg(FileStream fs, ConcurrentQueue<RawPacket> q, SharedState st)
        {
            fs.Position = 0;
            List<Iface> ifs = new List<Iface>();
            bool be = false;
            byte[] head = new byte[8];
            while (!st.Cancel && ReadFull(fs, head, 8))
            {
                uint type = R32(head, 0, false);
                if (type == 0x0A0D0D0A)
                {
                    byte[] bom = new byte[4];
                    if (!ReadFull(fs, bom, 4)) break;
                    be = (bom[0] == 0x1A && bom[1] == 0x2B && bom[2] == 0x3C && bom[3] == 0x4D);
                    uint slen = R32(head, 4, be);
                    ifs.Clear();
                    fs.Position += slen - 12;
                    continue;
                }
                uint len = R32(head, 4, be);
                type = R32(head, 0, be);
                if (len < 12 || len > 0x8000000) throw new InvalidDataException("Corrupt pcapng block.");
                byte[] body = new byte[len - 12 + 4];   // body + trailing length
                if (!ReadFull(fs, body, body.Length)) break;
                int blen = (int)len - 12;
                if (type == 1 && blen >= 8)
                {
                    Iface f = new Iface();
                    f.Link = R16(body, 0, be);
                    int o = 8;
                    while (o + 4 <= blen)
                    {
                        int code = R16(body, o, be), ol = R16(body, o + 2, be);
                        if (code == 0) break;
                        if (o + 4 + ol > blen) break;
                        if (code == 9 && ol >= 1)
                        {
                            byte v = body[o + 4];
                            int exp = v & 0x7F;
                            decimal u = (v & 0x80) == 0 ? 1m : 1m;
                            if ((v & 0x80) == 0) { for (int i = 0; i < exp; i++) u *= 10m; }
                            else { u = (decimal)Math.Pow(2, exp); }
                            f.UnitsPerSec = u;
                        }
                        else if (code == 2) f.Name = Encoding.UTF8.GetString(body, o + 4, ol);
                        else if (code == 3) f.Desc = Encoding.UTF8.GetString(body, o + 4, ol);
                        o += 4 + ((ol + 3) & ~3);
                    }
                    ifs.Add(f);
                }
                else if (type == 6 && blen >= 20)
                {
                    int id = (int)R32(body, 0, be);
                    ulong hi = R32(body, 4, be), lo = R32(body, 8, be);
                    ulong ts = (hi << 32) | lo;
                    int cap = (int)R32(body, 12, be), orig = (int)R32(body, 16, be);
                    if (cap < 0 || 20 + cap > blen) throw new InvalidDataException("Corrupt pcapng packet block.");
                    Iface f = id < ifs.Count ? ifs[id] : new Iface();
                    byte[] data = new byte[cap];
                    Buffer.BlockCopy(body, 20, data, 0, cap);
                    RawPacket r = new RawPacket();
                    r.Ticks = EpochTicks + (long)((decimal)ts * 10000000m / f.UnitsPerSec);
                    r.Data = data; r.OrigLen = orig; r.LinkType = f.Link; r.IfName = f.Name; r.IfDesc = f.Desc;
                    Push(q, r, st);
                }
                else if (type == 3 && blen >= 4)
                {
                    Iface f = ifs.Count > 0 ? ifs[0] : new Iface();
                    int orig = (int)R32(body, 0, be);
                    int cap = Math.Min(orig, blen - 4);
                    byte[] data = new byte[cap];
                    Buffer.BlockCopy(body, 4, data, 0, cap);
                    RawPacket r = new RawPacket();
                    r.Ticks = EpochTicks; r.Data = data; r.OrigLen = orig; r.LinkType = f.Link; r.IfName = f.Name;
                    Push(q, r, st);
                }
                st.Progress = fs.Position;
            }
        }

        // Writes classic pcap (nanosecond timestamps) that Wireshark opens directly.
        public static void Write(string path, IList<Packet> pkts, SharedState st)
        {
            try
            {
                st.Total = pkts.Count;
                int link = 1;
                if (pkts.Count > 0) link = pkts[0].LinkType;
                using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16))
                using (BinaryWriter w = new BinaryWriter(fs))
                {
                    w.Write((uint)0xA1B23C4D);
                    w.Write((ushort)2); w.Write((ushort)4);
                    w.Write((int)0); w.Write((uint)0);
                    w.Write((uint)262144);
                    w.Write((uint)link);
                    for (int i = 0; i < pkts.Count; i++)
                    {
                        if (st.Cancel) break;
                        Packet p = pkts[i];
                        long since = p.Ticks - EpochTicks;
                        w.Write((uint)(since / 10000000L));
                        w.Write((uint)((since % 10000000L) * 100L));
                        w.Write((uint)p.Data.Length);
                        w.Write((uint)p.OrigLen);
                        w.Write(p.Data);
                        st.Progress = i + 1;
                    }
                }
            }
            catch (Exception ex) { st.Error = ex.Message; }
            finally { st.Done = true; }
        }
    }

    // ------------------------------------------------ parse loop (runs on a runspace)
    public static class ParseLoop
    {
        // Consumes raw packets, dissects them in order and hands finished rows to the UI queue.
        public static void Run(ConcurrentQueue<RawPacket> raw, ConcurrentQueue<Packet> ui, Dissector d, SharedState st, SharedState producerDone, Predicate<Packet> keep)
        {
            while (!st.Cancel)
            {
                RawPacket r;
                int n = 0;
                while (n < 500 && raw.TryDequeue(out r))
                {
                    try
                    {
                        if (keep == null) ui.Enqueue(d.Process(r, ++d.Counter));
                        else
                        {
                            // capture filter: dissect (keeps TCP state right) but only number/keep matching packets
                            if (d.Counter == 0) d.ResetTime();
                            Packet p = d.Process(r, d.Counter + 1);
                            if (keep(p)) { d.Counter++; ui.Enqueue(p); }
                            else st.Progress++;                // count of packets filtered out
                        }
                    }
                    catch (Exception ex) { st.Error = ex.GetType().Name + ": " + ex.Message; }   // skip the bad packet, keep going
                    n++;
                }
                if (n == 0)
                {
                    if (producerDone != null && producerDone.Done && raw.IsEmpty) break;
                    Thread.Sleep(5);
                }
            }
            st.Done = true;
        }
    }

    // ------------------------------------------- live capture: real-time ETW consumer
    public static class EtwLive
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern ulong OpenTraceW(IntPtr logfile);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int ProcessTrace(ulong[] handles, uint count, IntPtr start, IntPtr end);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int CloseTrace(ulong handle);

        delegate void EventRecordCallback(IntPtr record);

        static ulong handle = 0xFFFFFFFFFFFFFFFFUL;
        static EventRecordCallback callback;
        static ConcurrentQueue<RawPacket> queue;
        static SharedState state;
        public static string IfName, IfDesc;     // set by the UI before capturing
        static readonly Guid NdisCapture = new Guid("2ED6006E-4729-4609-B423-3EE7BCD678EF");
        static readonly long FileTimeToTicks = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc).Ticks;

        static void OnEvent(IntPtr rec)
        {
            try
            {
                // EVENT_RECORD (x64): TimeStamp @16, ProviderId @24, EventDescriptor.Id @40, UserDataLength @86, UserData @96
                int id = Marshal.ReadInt16(rec, 40);
                if (id != 1001) return;
                byte[] g = new byte[16];
                Marshal.Copy(IntPtr.Add(rec, 24), g, 0, 16);
                if (new Guid(g) != NdisCapture) return;
                long ft = Marshal.ReadInt64(rec, 16);
                long kw = Marshal.ReadInt64(rec, 48);          // EventDescriptor.Keyword
                if ((kw & 0xC0000000L) != 0xC0000000L) return; // only complete single-event packets (KW_PACKET_START|END)
                int ulen = (ushort)Marshal.ReadInt16(rec, 86);
                IntPtr ud = Marshal.ReadIntPtr(rec, 96);
                if (ulen < 12 || ud == IntPtr.Zero) return;
                // Payload: MiniportIfIndex, LowerIfIndex, FragmentSize, Fragment[FragmentSize].
                // Locate the size field by checking it equals the number of bytes that follow it.
                int fragOff = -1, fragSize = 0;
                int[] tryAt = new int[] { 8, 4, 12, 0, 16 };
                for (int i = 0; i < tryAt.Length; i++)
                {
                    int k = tryAt[i];
                    if (k + 4 > ulen) continue;
                    int v = Marshal.ReadInt32(ud, k);
                    if (v > 0 && v == ulen - (k + 4)) { fragOff = k + 4; fragSize = v; break; }
                }
                if (fragOff < 0) { fragOff = 12; fragSize = ulen - 12; }
                if (fragSize <= 0) return;
                byte[] data = new byte[fragSize];
                Marshal.Copy(IntPtr.Add(ud, fragOff), data, 0, fragSize);
                RawPacket r = new RawPacket();
                r.Ticks = FileTimeToTicks + ft;
                r.Data = data; r.OrigLen = fragSize; r.IfName = IfName; r.IfDesc = IfDesc;
                r.Dir = (kw & 0x100000000L) != 0 ? 1 : (kw & 0x200000000L) != 0 ? 2 : 0;
                r.LinkType = (kw & 0x10000L) != 0 ? 105 : ((kw & 0x200L) != 0 ? 101 : 1);   // native 802.11 / mobile broadband (raw IP) / Ethernet
                queue.Enqueue(r);
                state.Count++;
            }
            catch (Exception) { }
        }

        // Blocks until Close() is called or the session ends. Run on its own runspace.
        public static string Run(string session, ConcurrentQueue<RawPacket> q, SharedState st)
        {
            if (IntPtr.Size != 8) return "Live capture requires 64-bit PowerShell.";
            queue = q; state = st;
            callback = new EventRecordCallback(OnEvent);
            IntPtr lf = Marshal.AllocHGlobal(448);
            IntPtr nameMem = Marshal.StringToHGlobalUni(session);
            try
            {
                byte[] zero = new byte[448];
                Marshal.Copy(zero, 0, lf, 448);
                Marshal.WriteIntPtr(lf, 8, nameMem);                                   // LoggerName
                Marshal.WriteInt32(lf, 28, 0x00000100 | 0x10000000);                   // REAL_TIME | EVENT_RECORD
                Marshal.WriteIntPtr(lf, 424, Marshal.GetFunctionPointerForDelegate(callback));
                handle = OpenTraceW(lf);
                if (handle == 0xFFFFFFFFFFFFFFFFUL || handle == 0)
                    return "OpenTrace failed (error " + Marshal.GetLastWin32Error() + ").";
                int rc = ProcessTrace(new ulong[] { handle }, 1, IntPtr.Zero, IntPtr.Zero);
                if (rc != 0 && !st.Cancel) return "ProcessTrace ended (error " + rc + ").";
                return null;
            }
            finally
            {
                Marshal.FreeHGlobal(nameMem);
                Marshal.FreeHGlobal(lf);
                handle = 0xFFFFFFFFFFFFFFFFUL;
            }
        }

        public static void Close()
        {
            ulong h = handle;
            if (h != 0xFFFFFFFFFFFFFFFFUL && h != 0) CloseTrace(h);
        }
    }
}

namespace PSShark
{
    // ------------------------------------------------------------- helpers
    internal class Ctx
    {
        public Packet P;
        public bool T;                 // build detail tree?
        public Dissector D;            // stateful pass only
        public TreeNode Root;
        public List<string> Chain = new List<string>();

        public TreeNode N(TreeNode parent, string text, int s, int l)
        {
            if (!T || parent == null) return null;
            TreeNode n = new TreeNode(text, s, l);
            parent.Children.Add(n);
            return n;
        }
    }

    internal static class U
    {
        public const string Arrow = "\u2192";

        public static int W(byte[] d, int o) { return (d[o] << 8) | d[o + 1]; }
        public static uint L(byte[] d, int o) { return ((uint)d[o] << 24) | ((uint)d[o + 1] << 16) | ((uint)d[o + 2] << 8) | d[o + 3]; }
        public static string Mac(byte[] d, int o)
        {
            return d[o].ToString("x2") + ":" + d[o + 1].ToString("x2") + ":" + d[o + 2].ToString("x2") + ":" +
                   d[o + 3].ToString("x2") + ":" + d[o + 4].ToString("x2") + ":" + d[o + 5].ToString("x2");
        }
        public static string MacName(byte[] d, int o)
        {
            bool bc = true;
            for (int i = 0; i < 6; i++) if (d[o + i] != 0xFF) bc = false;
            if (bc) return "Broadcast";
            if (d[o] == 0x01 && d[o + 1] == 0x00 && d[o + 2] == 0x5E) return "IPv4mcast_" + d[o + 3].ToString("x2") + ":" + d[o + 4].ToString("x2") + ":" + d[o + 5].ToString("x2");
            if (d[o] == 0x33 && d[o + 1] == 0x33) return "IPv6mcast_" + d[o + 2].ToString("x2") + ":" + d[o + 3].ToString("x2") + ":" + d[o + 4].ToString("x2") + ":" + d[o + 5].ToString("x2");
            if (d[o] == 0x01 && d[o + 1] == 0x80 && d[o + 2] == 0xC2 && d[o + 3] == 0 && d[o + 4] == 0)
            {
                if (d[o + 5] == 0x00) return "Nearest-Customer-Bridge";
                if (d[o + 5] == 0x0E) return "Nearest-Bridge";
                if (d[o + 5] == 0x03) return "Nearest-non-TPMR-Bridge";
            }
            return Mac(d, o);
        }
        public static string MacFull(byte[] d, int o)
        {
            string n = MacName(d, o), m = Mac(d, o);
            return n == m ? m : n + " (" + m + ")";
        }
        public static string Ip4(byte[] d, int o) { return d[o] + "." + d[o + 1] + "." + d[o + 2] + "." + d[o + 3]; }
        public static string Ip6(byte[] d, int o)
        {
            byte[] b = new byte[16];
            Array.Copy(d, o, b, 0, 16);
            return new IPAddress(b).ToString();
        }
        public static string Hx(long v, int digits) { return "0x" + v.ToString("x" + digits); }

        public static string Bits(int width, uint mask, uint val)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = width - 1; i >= 0; i--)
            {
                uint bit = 1u << i;
                sb.Append((mask & bit) != 0 ? ((val & bit) != 0 ? '1' : '0') : '.');
                if (i % 4 == 0 && i != 0) sb.Append(' ');
            }
            return sb.ToString();
        }

        public static string Rel(long ticks)
        {
            if (ticks < 0) return "-" + Rel(-ticks);
            return (ticks / 10000000L) + "." + ((ticks % 10000000L) * 100L).ToString("D9");
        }

        public static string HexStr(byte[] d, int o, int n)
        {
            StringBuilder sb = new StringBuilder();
            int m = Math.Min(n, 256);
            for (int i = 0; i < m; i++) sb.Append(d[o + i].ToString("x2"));
            return sb.ToString();
        }

        public static string Ascii(byte[] d, int o, int n)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < n; i++) { byte b = d[o + i]; sb.Append(b >= 32 && b < 127 ? (char)b : '.'); }
            return sb.ToString();
        }

        public static ushort Csum(byte[] d, int o, int n)
        {
            uint sum = 0;
            int i = 0;
            for (; i + 1 < n; i += 2) sum += (uint)((d[o + i] << 8) | d[o + i + 1]);
            if (i < n) sum += (uint)(d[o + i] << 8);
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)(~sum & 0xFFFF);
        }

        public static string Plural(long n, string w) { return n + " " + w + (n == 1 ? "" : "s"); }

        public static string Dscp(int v)
        {
            switch (v)
            {
                case 0: return "Default";
                case 8: return "Class Selector 1";
                case 16: return "Class Selector 2";
                case 24: return "Class Selector 3";
                case 32: return "Class Selector 4";
                case 40: return "Class Selector 5";
                case 48: return "Class Selector 6";
                case 56: return "Class Selector 7";
                case 10: return "Assured Forwarding 11";
                case 12: return "Assured Forwarding 12";
                case 14: return "Assured Forwarding 13";
                case 18: return "Assured Forwarding 21";
                case 20: return "Assured Forwarding 22";
                case 22: return "Assured Forwarding 23";
                case 26: return "Assured Forwarding 31";
                case 28: return "Assured Forwarding 32";
                case 30: return "Assured Forwarding 33";
                case 34: return "Assured Forwarding 41";
                case 36: return "Assured Forwarding 42";
                case 38: return "Assured Forwarding 43";
                case 46: return "Expedited Forwarding";
                default: return "Unknown";
            }
        }
        public static string DscpShort(int v)
        {
            if (v % 8 == 0) return "CS" + (v / 8);
            if (v == 46) return "EF";
            if (v == 10 || v == 12 || v == 14) return "AF1" + ((v - 8) / 2);
            if (v == 18 || v == 20 || v == 22) return "AF2" + ((v - 16) / 2);
            if (v == 26 || v == 28 || v == 30) return "AF3" + ((v - 24) / 2);
            if (v == 34 || v == 36 || v == 38) return "AF4" + ((v - 32) / 2);
            return v.ToString();
        }
        public static string Ecn(int v)
        {
            switch (v) { case 0: return "Not-ECT"; case 1: return "ECT(1)"; case 2: return "ECT(0)"; default: return "CE"; }
        }
        public static string EcnLong(int v)
        {
            switch (v) { case 0: return "Not ECN-Capable Transport"; case 1: return "ECN Capable Transport(1)"; case 2: return "ECN Capable Transport(0)"; default: return "Congestion Experienced"; }
        }

        public static string ProtoName(int p)
        {
            switch (p)
            {
                case 0: return "HOPOPT"; case 1: return "ICMP"; case 2: return "IGMP"; case 4: return "IPIP"; case 6: return "TCP";
                case 17: return "UDP"; case 41: return "IPv6"; case 47: return "GRE"; case 50: return "ESP"; case 51: return "AH";
                case 58: return "ICMPv6"; case 89: return "OSPF"; case 103: return "PIM"; case 112: return "VRRP"; case 132: return "SCTP";
                default: return "Unknown";
            }
        }

        public static string EtherName(int t)
        {
            switch (t)
            {
                case 0x0800: return "IPv4"; case 0x0806: return "ARP"; case 0x86DD: return "IPv6"; case 0x8100: return "802.1Q Virtual LAN";
                case 0x88A8: return "802.1ad Provider Bridging"; case 0x88CC: return "LLDP"; case 0x888E: return "802.1X Authentication";
                case 0x8847: return "MPLS label switched packet"; case 0x0842: return "Wake-on-LAN"; case 0x8035: return "RARP";
                case 0x9000: return "Loopback"; default: return "Unknown";
            }
        }
    }

    internal class TcpStream
    {
        public int Index;
        public bool[] Has = new bool[2];
        public uint[] Base = new uint[2];
        public bool[] HasNext = new bool[2];
        public uint[] Next = new uint[2];
        public int[] Ws = new int[] { -1, -1 };
        public int LastKa = -1;
        public bool Tls, Tls13;
        public bool[] Enc = new bool[2];
        public Reasm[] R = new Reasm[2];
        public List<uint[]>[] Delivered = new List<uint[]>[2];     // {first seq, end seq, frame} of completed PDUs
        public string TlsLabel;
    }

    // -------------------------------------------------------------- dissector
    public partial class Dissector
    {
        public int Counter;
        long firstTicks, prevTicks;
        bool haveFirst;
        Dictionary<string, TcpStream> streams = new Dictionary<string, TcpStream>();
        int nextStream;

        static readonly long EpochTicks = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).Ticks;

        // Time zero is the first *kept* packet when a capture filter is active.
        public void ResetTime() { haveFirst = false; }

        // Stateful pass: one call per packet, in capture order. Produces the packet-list row.
        public Packet Process(RawPacket r, int no)
        {
            Packet p = new Packet();
            p.No = no; p.Data = r.Data; p.Ticks = r.Ticks; p.OrigLen = r.OrigLen; p.LinkType = r.LinkType; p.IfName = r.IfName; p.IfDesc = r.IfDesc; p.Dir = r.Dir;
            p.Length = r.OrigLen;
            if (!haveFirst) { firstTicks = r.Ticks; prevTicks = r.Ticks; haveFirst = true; }
            p.SinceFirst = r.Ticks - firstTicks;
            p.DeltaPrev = r.Ticks - prevTicks;
            prevTicks = r.Ticks;
            p.Time = U.Rel(p.SinceFirst);
            Ctx c = new Ctx();
            c.P = p; c.D = this; c.T = false;
            Run(c);
            return p;
        }

        // Stateless pass: rebuilds the protocol tree for one selected packet (uses values stored by Process).
        public static List<TreeNode> BuildTree(Packet orig)
        {
            Packet p = orig.Copy();
            Ctx c = new Ctx();
            c.P = p; c.T = true; c.D = null; c.Root = new TreeNode("", 0, 0);
            TreeNode frame = new TreeNode("", 0, p.Data.Length);
            c.Root.Children.Add(frame);
            byte[] d = p.Data;
            string ifn = string.IsNullOrEmpty(p.IfName) ? "unnamed interface" : "interface " + p.IfName;
            frame.Text = "Frame " + p.No + ": Packet, " + U.Plural(p.OrigLen, "byte") + " on wire (" + (p.OrigLen * 8) + " bits), " +
                         U.Plural(d.Length, "byte") + " captured (" + (d.Length * 8) + " bits) on " + ifn + ", id 0";
            DateTime utc = new DateTime(p.Ticks, DateTimeKind.Utc);
            DateTime loc = utc.ToLocalTime();
            string tz = TimeZoneInfo.Local.IsDaylightSavingTime(loc) ? TimeZoneInfo.Local.DaylightName : TimeZoneInfo.Local.StandardName;
            long sub = p.Ticks % 10000000L;
            TreeNode iface = c.N(frame, "Interface id: 0 (" + (string.IsNullOrEmpty(p.IfName) ? "unknown" : p.IfName) + ")", 0, 0);
            c.N(iface, "Interface name: " + (string.IsNullOrEmpty(p.IfName) ? "unknown" : p.IfName), 0, 0);
            if (!string.IsNullOrEmpty(p.IfDesc)) c.N(iface, "Interface description: " + p.IfDesc, 0, 0);
            c.N(frame, "Encapsulation type: " + (p.LinkType == 1 ? "Ethernet (1)" : p.LinkType == 101 ? "Raw IP (7)" : p.LinkType == 0 ? "NULL/Loopback (15)" : "Link type " + p.LinkType), 0, 0);
            c.N(frame, "Arrival Time: " + loc.ToString("MMM d, yyyy HH:mm:ss.fffffff", CultureInfo.InvariantCulture) + "00 " + tz, 0, 0);
            c.N(frame, "UTC Arrival Time: " + utc.ToString("MMM d, yyyy HH:mm:ss.fffffff", CultureInfo.InvariantCulture) + "00 UTC", 0, 0);
            c.N(frame, "Epoch Arrival Time: " + U.Rel(p.Ticks - EpochTicks), 0, 0);
            c.N(frame, "[Time shift for this packet: 0.000000000 seconds]", 0, 0);
            c.N(frame, "[Time delta from previous captured frame: " + U.Rel(p.DeltaPrev) + " seconds]", 0, 0);
            c.N(frame, "[Time since reference or first frame: " + U.Rel(p.SinceFirst) + " seconds]", 0, 0);
            c.N(frame, "Frame Number: " + p.No, 0, 0);
            c.N(frame, "Frame Length: " + U.Plural(p.OrigLen, "byte") + " (" + (p.OrigLen * 8) + " bits)", 0, 0);
            c.N(frame, "Capture Length: " + U.Plural(d.Length, "byte") + " (" + (d.Length * 8) + " bits)", 0, 0);
            c.N(frame, "[Frame is marked: False]", 0, 0);
            c.N(frame, "[Frame is ignored: False]", 0, 0);
            TreeNode chainNode = c.N(frame, "", 0, 0);
            TreeNode ruleNode = c.N(frame, "", 0, 0);
            TreeNode ruleExpr = c.N(frame, "", 0, 0);
            Run(c);
            chainNode.Text = "[Protocols in frame: " + string.Join(":", c.Chain.ToArray()) + "]";
            ruleNode.Text = "[Coloring Rule Name: " + p.RuleName + "]";
            ruleExpr.Text = "[Coloring Rule String: " + p.RuleExpr + "]";
            return c.Root.Children;
        }

        static void Run(Ctx c)
        {
            Packet p = c.P;
            if (!c.T) { p.Protocol = "Frame"; p.Info = ""; p.Source = ""; p.Destination = ""; }
            try { L2(c); }
            catch (IndexOutOfRangeException) { Malformed(c); }
            catch (ArgumentException) { Malformed(c); }
            Colorize(p);
            if (!c.T) p.Chain = string.Join(":", c.Chain.ToArray());
        }

        static void Malformed(Ctx c)
        {
            Packet p = c.P;
            if (p.Data.Length >= p.OrigLen && !c.T) p.Info += " [Malformed Packet]";
            if (c.T) c.N(c.Root, "[Malformed Packet: truncated or invalid data]", 0, 0);
        }

        static void Colorize(Packet p)
        {
            // Midnight Violet dark palette: each protocol family keeps a distinct, desaturated
            // background so it reads on the dark grid; foreground defaults to a single light tint
            // and is overridden only for rows that must stand out as a problem (Wireshark does the same).
            p.Bg = "#20203F"; p.Fg = "#E8E8FF"; p.RuleName = "Default"; p.RuleExpr = "";
            string pr = p.Protocol;
            if (p.TcpNote != null && p.TcpNote != "TCP Keep-Alive" && p.TcpNote != "TCP Keep-Alive ACK")
            { p.Bg = "#3A1414"; p.Fg = "#FF6B6B"; p.RuleName = "Bad TCP"; p.RuleExpr = "tcp.analysis.flags && !tcp.analysis.window_update && !tcp.analysis.keep_alive && !tcp.analysis.keep_alive_ack"; return; }
            if (pr == "HTTP") { p.Bg = "#1F3A1A"; p.RuleName = "HTTP"; p.RuleExpr = "http || tcp.port == 80 || http2"; return; }
            bool tcp = (":" + p.Chain + ":").IndexOf(":tcp:") >= 0 || pr == "TCP" || pr.StartsWith("TLS") || pr == "SSL";
            if (tcp)
            {
                if (p.Info != null && p.Info.IndexOf("[RST") >= 0) { p.Bg = "#5C0000"; p.Fg = "#FFD873"; p.RuleName = "TCP RST"; p.RuleExpr = "tcp.flags.reset eq 1"; return; }
                if (p.Info != null && (p.Info.IndexOf("[SYN") >= 0 || p.Info.IndexOf("[FIN") >= 0)) { p.Bg = "#3A3A3A"; p.RuleName = "TCP SYN/FIN"; p.RuleExpr = "tcp.flags & 0x02 || tcp.flags.fin == 1"; return; }
                p.Bg = "#26264D"; p.RuleName = "TCP"; p.RuleExpr = "tcp"; return;
            }
            if (pr == "ICMP" || pr == "ICMPv6") { p.Bg = "#3A1F3A"; p.RuleName = "ICMP"; p.RuleExpr = "icmp || icmpv6"; return; }
            if (pr == "ARP") { p.Bg = "#332B14"; p.RuleName = "ARP"; p.RuleExpr = "arp"; return; }
            if (pr == "OSPF") { p.Bg = "#3D3015"; p.RuleName = "Routing"; p.RuleExpr = "hsrp || eigrp || ospf || bgp || cdp || vrrp || carp || gvrp || igmp || ismp"; return; }
            if ((":" + p.Chain + ":").IndexOf(":udp:") >= 0 || pr == "UDP") { p.Bg = "#142A3D"; p.RuleName = "UDP"; p.RuleExpr = "udp"; return; }
            if (p.Destination == "Broadcast") { p.RuleName = "Broadcast"; p.RuleExpr = "eth[0] & 1"; }
        }

        // ----------------------------------------------------------- layer 2
        static void L2(Ctx c)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            int etype = 0, off = 0;
            switch (p.LinkType)
            {
                case 1:
                    c.Chain.Add("eth");
                    if (!c.T) { p.Destination = U.MacName(d, 0); p.Source = U.MacName(d, 6); }
                    etype = U.W(d, 12);
                    off = 14;
                    p.EthOff = 0;
                    if (etype > 1500) p.EthType = etype;
                    if (etype <= 1500) { Llc(c, off, etype); return; }
                    TreeNode eth = null;
                    if (c.T)
                    {
                        eth = c.N(c.Root, "Ethernet II, Src: " + U.MacFull(d, 6) + ", Dst: " + U.MacFull(d, 0), 0, 14);
                        MacNode(c, eth, "Destination", d, 0);
                        MacNode(c, eth, "Source", d, 6);
                        c.N(eth, "Type: " + U.EtherName(etype) + " (" + U.Hx(etype, 4) + ")", 12, 2);
                    }
                    c.Chain.Add("ethertype");
                    while (etype == 0x8100 || etype == 0x88A8)
                    {
                        int tci = U.W(d, off);
                        int real = U.W(d, off + 2);
                        p.VlanId = tci & 0xFFF; p.VlanPri = tci >> 13;
                        c.Chain.Add("vlan");
                        if (c.T)
                        {
                            TreeNode v = c.N(c.Root, "802.1Q Virtual LAN, PRI: " + (tci >> 13) + ", DEI: " + ((tci >> 12) & 1) + ", ID: " + (tci & 0xFFF), off, 4);
                            c.N(v, U.Bits(16, 0xE000, (uint)tci) + " = Priority: " + (tci >> 13 == 0 ? "Best Effort (default)" : "Priority " + (tci >> 13)) + " (" + (tci >> 13) + ")", off, 2);
                            c.N(v, U.Bits(16, 0x1000, (uint)tci) + " = DEI: " + (((tci >> 12) & 1) == 1 ? "Eligible" : "Ineligible"), off, 2);
                            c.N(v, U.Bits(16, 0x0FFF, (uint)tci) + " = ID: " + (tci & 0xFFF), off, 2);
                            c.N(v, "Type: " + U.EtherName(real) + " (" + U.Hx(real, 4) + ")", off + 2, 2);
                        }
                        etype = real;
                        off += 4;
                    }
                    break;
                case 0:
                    {
                        int fam = d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24);
                        etype = fam == 2 ? 0x0800 : 0x86DD;
                        off = 4;
                        c.N(c.Root, "Null/Loopback", 0, 4);
                        break;
                    }
                case 101:
                case 12:
                case 14:
                case 228:
                case 229:
                    etype = (d[0] >> 4) == 6 ? 0x86DD : 0x0800;
                    break;
                case 105:
                    Wifi(c);
                    return;
                case 113:
                    etype = U.W(d, 14);
                    off = 16;
                    c.N(c.Root, "Linux cooked capture v1", 0, 16);
                    break;
                default:
                    p.Protocol = "Link-" + p.LinkType; p.Info = "Unsupported link type";
                    return;
            }
            Network(c, etype, off);
        }

        static void Wifi(Ctx c)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            c.Chain.Add("wlan");
            int fc = d[0] | (d[1] << 8);
            int type = (fc >> 2) & 3, sub = (fc >> 4) & 0xF;
            p.Protocol = "802.11";
            string name;
            if (type == 0)
            {
                string[] m = { "Association Request", "Association Response", "Reassociation Request", "Reassociation Response", "Probe Request", "Probe Response", "Timing Advertisement", "Reserved", "Beacon frame", "ATIM", "Disassociation", "Authentication", "Deauthentication", "Action", "Action No Ack", "Reserved" };
                name = m[sub];
            }
            else if (type == 1)
            {
                name = sub == 7 ? "Block Ack Request" : sub == 8 ? "Block Ack" : sub == 9 ? "Power-Save Poll" : sub == 10 ? "Request-to-send" :
                       sub == 11 ? "Clear-to-send" : sub == 12 ? "Acknowledgement" : sub == 13 ? "CF-End" : sub == 14 ? "CF-End + CF-Ack" : "Control (" + sub + ")";
            }
            else if (type == 2)
            {
                string[] m = { "Data", "Data + CF-Ack", "Data + CF-Poll", "Data + CF-Ack + CF-Poll", "Null function (No data)", "Null + CF-Ack", "Null + CF-Poll", "Null + CF-Ack + CF-Poll", "QoS Data", "QoS Data + CF-Ack", "QoS Data + CF-Poll", "QoS Data + CF-Ack + CF-Poll", "QoS Null function (No data)", "Reserved", "QoS CF-Poll (No data)", "QoS CF-Ack + CF-Poll (No data)" };
                name = m[sub];
            }
            else name = "Extension";
            p.Info = name + ", Flags=" + ((fc >> 8) & 0xFF).ToString("x2");
            if (d.Length >= 16 && !(type == 1 && (sub == 12 || sub == 11)))
            {
                p.Destination = U.MacName(d, 4);
                if (d.Length >= 22) p.Source = U.MacName(d, 10);
            }
            if (c.T)
            {
                TreeNode n = c.N(c.Root, "IEEE 802.11 " + name, 0, Math.Min(d.Length, 24));
                c.N(n, "Frame Control Field: " + U.Hx(fc, 4), 0, 2);
                c.N(n, "Type/Subtype: " + name + " (" + ((type << 4) | sub) + ")", 0, 1);
                if (d.Length >= 10) c.N(n, "Receiver address: " + U.MacFull(d, 4), 4, 6);
                if (d.Length >= 16) c.N(n, "Transmitter address: " + U.MacFull(d, 10), 10, 6);
                c.N(n, "Note: Wi-Fi frames are labelled but their bodies are not decoded by PSShark.", 0, 0);
            }
        }

        static void MacNode(Ctx c, TreeNode parent, string label, byte[] d, int o)
        {
            if (!c.T) return;
            TreeNode n = c.N(parent, label + ": " + U.MacFull(d, o), o, 6);
            uint v = (uint)((d[o] << 16) | (d[o + 1] << 8) | d[o + 2]);
            c.N(n, U.Bits(24, 0x020000, v) + " = LG bit: " + ((d[o] & 2) != 0 ? "Locally administered address (this is NOT the factory default)" : "Globally unique address (factory default)"), o, 3);
            c.N(n, U.Bits(24, 0x010000, v) + " = IG bit: " + ((d[o] & 1) != 0 ? "Group address (multicast/broadcast)" : "Individual address (unicast)"), o, 3);
        }

        static void Llc(Ctx c, int off, int length)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            int dsap = d[off], ssap = d[off + 1], ctl = d[off + 2];
            c.Chain.Add("eth");
            c.Chain.Add("llc");
            if (c.T)
            {
                TreeNode e = c.N(c.Root, "IEEE 802.3 Ethernet ", 0, 14);
                MacNode(c, e, "Destination", d, 0);
                MacNode(c, e, "Source", d, 6);
                c.N(e, "Length: " + length, 12, 2);
                TreeNode l = c.N(c.Root, "Logical-Link Control", 14, 3);
                c.N(l, "DSAP: " + (dsap == 0x42 ? "Spanning Tree BPDU" : dsap == 0xAA ? "SNAP" : "Unknown") + " (" + U.Hx(dsap, 2) + ")", 14, 1);
                c.N(l, "SSAP: " + (ssap == 0x42 ? "Spanning Tree BPDU" : ssap == 0xAA ? "SNAP" : "Unknown") + " (" + U.Hx(ssap, 2) + ")", 15, 1);
                c.N(l, "Control field: U, func=UI (" + U.Hx(ctl, 2) + ")", 16, 1);
            }
            if (dsap == 0x42 && ssap == 0x42) { Stp(c, off + 3); return; }
            if (dsap == 0xAA && ssap == 0xAA)
            {
                int oui = (d[off + 3] << 16) | (d[off + 4] << 8) | d[off + 5];
                int pid = U.W(d, off + 6);
                if (oui == 0) { Network(c, pid, off + 8); return; }
                p.Protocol = (oui == 0x00000C && pid == 0x2000) ? "CDP" : "LLC";
                p.Info = (oui == 0x00000C && pid == 0x2000) ? "Cisco Discovery Protocol" : "SNAP, OUI " + U.Hx(oui, 6) + ", PID " + U.Hx(pid, 4);
                return;
            }
            p.Protocol = "LLC";
            p.Info = "SAP " + U.Hx(dsap, 2) + " " + ((ssap & 1) != 0 ? "Response" : "Command") + ", ctrl " + U.Hx(ctl, 2);
        }

        static void Stp(Ctx c, int off)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            c.Chain.Add("stp");
            int ver = d[off + 2], type = d[off + 3];
            p.Protocol = "STP";
            if (type == 0x80) { p.Info = "Conf. TC + Topology Change Notification"; if (c.T) c.N(c.Root, "Spanning Tree Protocol", off, 4); return; }
            int rp = U.W(d, off + 5);
            string root = (rp & 0xF000) + "/" + (rp & 0x0FFF) + "/" + U.Mac(d, off + 7);
            uint cost = U.L(d, off + 13);
            int port = U.W(d, off + 25);
            p.Info = (type == 0x02 ? "RST. " : "Conf. ") + "Root = " + root + "  Cost = " + cost + "  Port = " + U.Hx(port, 4);
            if (type == 0x00 && (d[off + 4] & 0x01) != 0) p.Info = "Conf. TC + Root = " + root + "  Cost = " + cost + "  Port = " + U.Hx(port, 4);
            if (c.T)
            {
                TreeNode s = c.N(c.Root, "Spanning Tree Protocol", off, Math.Min(35, d.Length - off));
                c.N(s, "Protocol Identifier: Spanning Tree Protocol (0x0000)", off, 2);
                c.N(s, "Protocol Version Identifier: " + (ver == 0 ? "Spanning Tree (0)" : ver == 2 ? "Rapid Spanning Tree (2)" : ver.ToString()), off + 2, 1);
                c.N(s, "BPDU Type: " + (type == 0 ? "Configuration (0x00)" : type == 2 ? "Rapid/Multiple Spanning Tree (0x02)" : U.Hx(type, 2)), off + 3, 1);
                c.N(s, "BPDU flags: " + U.Hx(d[off + 4], 2), off + 4, 1);
                TreeNode r = c.N(s, "Root Identifier: " + (rp & 0xF000) + " / " + (rp & 0x0FFF) + " / " + U.Mac(d, off + 7), off + 5, 8);
                c.N(r, "Root Bridge Priority: " + (rp & 0xF000), off + 5, 2);
                c.N(r, "Root Bridge System ID Extension: " + (rp & 0x0FFF), off + 5, 2);
                c.N(r, "Root Bridge System ID: " + U.Mac(d, off + 7), off + 7, 6);
                c.N(s, "Root Path Cost: " + cost, off + 13, 4);
                int bp = U.W(d, off + 17);
                TreeNode b = c.N(s, "Bridge Identifier: " + (bp & 0xF000) + " / " + (bp & 0x0FFF) + " / " + U.Mac(d, off + 19), off + 17, 8);
                c.N(b, "Bridge Priority: " + (bp & 0xF000), off + 17, 2);
                c.N(b, "Bridge System ID Extension: " + (bp & 0x0FFF), off + 17, 2);
                c.N(b, "Bridge System ID: " + U.Mac(d, off + 19), off + 19, 6);
                c.N(s, "Port identifier: " + U.Hx(port, 4), off + 25, 2);
                c.N(s, "Message Age: " + (U.W(d, off + 27) / 256), off + 27, 2);
                c.N(s, "Max Age: " + (U.W(d, off + 29) / 256), off + 29, 2);
                c.N(s, "Hello Time: " + (U.W(d, off + 31) / 256), off + 31, 2);
                c.N(s, "Forward Delay: " + (U.W(d, off + 33) / 256), off + 33, 2);
            }
        }

        // ----------------------------------------------------------- layer 3
        static void Network(Ctx c, int etype, int off)
        {
            Packet p = c.P;
            switch (etype)
            {
                case 0x0800: IPv4(c, off); return;
                case 0x86DD: IPv6(c, off); return;
                case 0x0806: Arp(c, off); return;
            }
            string n = U.EtherName(etype);
            p.Protocol = n == "Unknown" ? "Ethernet" : n == "802.1X Authentication" ? "EAPOL" : n;
            p.Info = n == "Unknown" ? "Ethertype " + U.Hx(etype, 4) : n;
            Payload(c, off, p.Data.Length, "Data");
        }

        static void Payload(Ctx c, int off, int end, string label)
        {
            if (!c.T || end <= off) return;
            int n = end - off;
            TreeNode t = c.N(c.Root, label + " (" + n + " bytes)", off, n);
            c.N(t, "Data: " + U.HexStr(c.P.Data, off, n), off, n);
            c.N(t, "[Length: " + n + "]", off, n);
        }

        static void Arp(Ctx c, int off)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            c.Chain.Add("arp");
            int hw = U.W(d, off), pt = U.W(d, off + 2), hl = d[off + 4], pl = d[off + 5], op = U.W(d, off + 6);
            string smac = U.Mac(d, off + 8), sip = U.Ip4(d, off + 14), tmac = U.Mac(d, off + 18), tip = U.Ip4(d, off + 24);
            p.Protocol = "ARP";
            p.ArpOff = off;
            if (op == 1) p.Info = (sip == tip) ? "ARP Announcement for " + sip : "Who has " + tip + "? Tell " + sip;
            else if (op == 2) p.Info = sip + " is at " + smac;
            else p.Info = "Opcode " + op;
            if (c.T)
            {
                string opn = op == 1 ? "request" : op == 2 ? "reply" : "unknown";
                TreeNode a = c.N(c.Root, "Address Resolution Protocol (" + opn + ")", off, 28);
                c.N(a, "Hardware type: " + (hw == 1 ? "Ethernet" : "Unknown") + " (" + hw + ")", off, 2);
                c.N(a, "Protocol type: " + U.EtherName(pt) + " (" + U.Hx(pt, 4) + ")", off + 2, 2);
                c.N(a, "Hardware size: " + hl, off + 4, 1);
                c.N(a, "Protocol size: " + pl, off + 5, 1);
                c.N(a, "Opcode: " + opn + " (" + op + ")", off + 6, 2);
                c.N(a, "Sender MAC address: " + U.MacFull(d, off + 8), off + 8, 6);
                c.N(a, "Sender IP address: " + sip, off + 14, 4);
                c.N(a, "Target MAC address: " + U.MacFull(d, off + 18), off + 18, 6);
                c.N(a, "Target IP address: " + tip, off + 24, 4);
            }
        }

        static void IPv4(Ctx c, int off)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            c.Chain.Add("ip");
            int ihl = (d[off] & 0xF) * 4;
            int tos = d[off + 1], total = U.W(d, off + 2), id = U.W(d, off + 4), ff = U.W(d, off + 6);
            int ttl = d[off + 8], proto = d[off + 9], csum = U.W(d, off + 10);
            string src = U.Ip4(d, off + 12), dst = U.Ip4(d, off + 16);
            p.Source = src; p.Destination = dst; p.SrcIp = src; p.DstIp = dst; p.Ttl = ttl;
            p.Protocol = "IPv4";
            int end = (total == 0 || total < ihl) ? d.Length : Math.Min(off + total, d.Length);
            p.L3Off = off; p.L3Ver = 4; p.L3End = end;
            int fragOff = (ff & 0x1FFF) * 8;
            bool mf = (ff & 0x2000) != 0;
            if (c.T)
            {
                TreeNode ip = c.N(c.Root, "Internet Protocol Version 4, Src: " + src + ", Dst: " + dst, off, ihl);
                c.N(ip, U.Bits(8, 0xF0, (uint)d[off]) + " = Version: 4", off, 1);
                c.N(ip, U.Bits(8, 0x0F, (uint)d[off]) + " = Header Length: " + ihl + " bytes (" + (ihl / 4) + ")", off, 1);
                TreeNode ds = c.N(ip, "Differentiated Services Field: " + U.Hx(tos, 2) + " (DSCP: " + U.DscpShort(tos >> 2) + ", ECN: " + U.Ecn(tos & 3) + ")", off + 1, 1);
                c.N(ds, U.Bits(8, 0xFC, (uint)tos) + " = Differentiated Services Codepoint: " + U.Dscp(tos >> 2) + " (" + (tos >> 2) + ")", off + 1, 1);
                c.N(ds, U.Bits(8, 0x03, (uint)tos) + " = Explicit Congestion Notification: " + U.EcnLong(tos & 3) + " (" + (tos & 3) + ")", off + 1, 1);
                c.N(ip, "Total Length: " + total, off + 2, 2);
                c.N(ip, "Identification: " + U.Hx(id, 4) + " (" + id + ")", off + 4, 2);
                string fl = (ff & 0x4000) != 0 ? "Don't fragment" : mf ? "More fragments" : "";
                TreeNode f = c.N(ip, U.Bits(8, 0xE0, (uint)(ff >> 8)) + " = Flags: " + U.Hx(ff >> 13, 1) + (fl.Length > 0 ? ", " + fl : ""), off + 6, 1);
                c.N(f, U.Bits(8, 0x80, (uint)(ff >> 8)) + " = Reserved bit: " + ((ff & 0x8000) != 0 ? "Set" : "Not set"), off + 6, 1);
                c.N(f, U.Bits(8, 0x40, (uint)(ff >> 8)) + " = Don't fragment: " + ((ff & 0x4000) != 0 ? "Set" : "Not set"), off + 6, 1);
                c.N(f, U.Bits(8, 0x20, (uint)(ff >> 8)) + " = More fragments: " + (mf ? "Set" : "Not set"), off + 6, 1);
                c.N(ip, U.Bits(16, 0x1FFF, (uint)ff) + " = Fragment Offset: " + fragOff, off + 6, 2);
                c.N(ip, "Time to Live: " + ttl, off + 8, 1);
                c.N(ip, "Protocol: " + U.ProtoName(proto) + " (" + proto + ")", off + 9, 1);
                c.N(ip, "Header Checksum: " + U.Hx(csum, 4) + " [validation disabled]", off + 10, 2);
                c.N(ip, "[Header checksum status: Unverified]", off + 10, 2);
                c.N(ip, "Source Address: " + src, off + 12, 4);
                c.N(ip, "Destination Address: " + dst, off + 16, 4);
                if (ihl > 20) c.N(ip, "Options: (" + (ihl - 20) + " bytes)", off + 20, ihl - 20);
            }
            if (fragOff != 0 || mf)
            {
                p.Info = "Fragmented IP protocol (proto=" + U.ProtoName(proto) + " " + proto + ", off=" + fragOff + ", ID=" + id.ToString("x4") + ")";
                return;
            }
            Transport(c, proto, off + ihl, end);
        }

        static void IPv6(Ctx c, int off)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            c.Chain.Add("ipv6");
            uint vtf = U.L(d, off);
            int plen = U.W(d, off + 4), nh = d[off + 6], hlim = d[off + 7];
            string src = U.Ip6(d, off + 8), dst = U.Ip6(d, off + 24);
            p.Source = src; p.Destination = dst; p.SrcIp = src; p.DstIp = dst; p.Ttl = hlim;
            p.Protocol = "IPv6";
            int poff = off + 40;
            int end = plen == 0 ? d.Length : Math.Min(poff + plen, d.Length);
            p.L3Off = off; p.L3Ver = 6; p.L3End = end;
            if (c.T)
            {
                int tc = (int)((vtf >> 20) & 0xFF);
                TreeNode ip = c.N(c.Root, "Internet Protocol Version 6, Src: " + src + ", Dst: " + dst, off, 40);
                c.N(ip, "0110 .... = Version: 6", off, 1);
                c.N(ip, U.Bits(32, 0x0FF00000, vtf) + " = Traffic Class: " + U.Hx(tc, 2) + " (DSCP: " + U.DscpShort(tc >> 2) + ", ECN: " + U.Ecn(tc & 3) + ")", off, 4);
                c.N(ip, U.Bits(32, 0x000FFFFF, vtf) + " = Flow Label: " + U.Hx(vtf & 0xFFFFF, 5), off, 4);
                c.N(ip, "Payload Length: " + plen, off + 4, 2);
                c.N(ip, "Next Header: " + U.ProtoName(nh) + " (" + nh + ")", off + 6, 1);
                c.N(ip, "Hop Limit: " + hlim, off + 7, 1);
                c.N(ip, "Source Address: " + src, off + 8, 16);
                c.N(ip, "Destination Address: " + dst, off + 24, 16);
            }
            while (nh == 0 || nh == 43 || nh == 60)
            {
                int next = d[poff];
                int hl = (d[poff + 1] + 1) * 8;
                if (c.T) c.N(c.Root, (nh == 0 ? "IPv6 Hop-by-Hop Option" : nh == 43 ? "Routing Header for IPv6" : "Destination Options for IPv6"), poff, hl);
                nh = next;
                poff += hl;
            }
            if (nh == 44)
            {
                int fnh = d[poff], fo = U.W(d, poff + 2);
                p.Info = "Fragmented IPv6 protocol (nxt=" + U.ProtoName(fnh) + " (" + fnh + ") off=" + (fo >> 3) + " id=" + U.Hx(U.L(d, poff + 4), 8) + ")";
                if (c.T) c.N(c.Root, "Fragment Header for IPv6", poff, 8);
                return;
            }
            if (nh == 59) { p.Info = "No Next Header for IPv6"; return; }
            Transport(c, nh, poff, end);
        }

        static void Transport(Ctx c, int proto, int off, int end)
        {
            Packet p = c.P;
            p.L4Off = off; p.L4End = end; p.L4Proto = proto;
            switch (proto)
            {
                case 1: Icmp(c, off, end); return;
                case 2: Igmp(c, off, end); return;
                case 6: Tcp(c, off, end); return;
                case 17: Udp(c, off, end); return;
                case 58: Icmp6(c, off, end); return;
            }
            string n = U.ProtoName(proto);
            p.Protocol = n == "Unknown" ? p.Protocol : n;
            p.Info = n == "Unknown" ? "Protocol " + proto : n;
            Payload(c, off, end, "Data");
        }
    }
}

namespace PSShark
{
    internal class OptEntry { public int Kind, Start, Len; }

    public partial class Dissector
    {
        // ---------------------------------------------------------------- ICMP
        static string IcmpType(int t, int code)
        {
            switch (t)
            {
                case 0: return "Echo (ping) reply";
                case 3:
                    {
                        string[] n = { "Network unreachable", "Host unreachable", "Protocol unreachable", "Port unreachable", "Fragmentation needed", "Source route failed" };
                        return "Destination unreachable (" + (code < n.Length ? n[code] : code == 13 ? "Communication administratively filtered" : "code " + code) + ")";
                    }
                case 4: return "Source quench (flow control)";
                case 5: return "Redirect (" + (code == 0 ? "Redirect for network" : code == 1 ? "Redirect for host" : "code " + code) + ")";
                case 8: return "Echo (ping) request";
                case 9: return "Router advertisement";
                case 10: return "Router solicitation";
                case 11: return "Time-to-live exceeded (" + (code == 0 ? "Time to live exceeded in transit" : "Fragment reassembly time exceeded") + ")";
                case 12: return "Parameter problem";
                case 13: return "Timestamp request";
                case 14: return "Timestamp reply";
                default: return "Type " + t;
            }
        }

        static void Icmp(Ctx c, int off, int end)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            c.Chain.Add("icmp");
            p.Protocol = "ICMP";
            int t = d[off], code = d[off + 1], csum = U.W(d, off + 2);
            string name = IcmpType(t, code);
            if (t == 0 || t == 8)
            {
                int id = U.W(d, off + 4), sq = U.W(d, off + 6);
                int ttl = p.Ttl;
                p.Info = "Echo (ping) " + (t == 8 ? "request" : "reply").PadRight(7) + "  id=" + U.Hx(id, 4) + ", seq=" + sq + "/" + (((sq & 0xFF) << 8) | (sq >> 8)) + ", ttl=" + ttl;
            }
            else p.Info = name;
            if (c.T)
            {
                TreeNode n = c.N(c.Root, "Internet Control Message Protocol", off, end - off);
                bool sub = (t == 3 || t == 5 || t == 11);
                c.N(n, "Type: " + t + " (" + (sub ? name.Substring(0, name.IndexOf('(')).Trim() : name) + ")", off, 1);
                c.N(n, "Code: " + code + (sub ? " (" + name.Substring(name.IndexOf('(') + 1).TrimEnd(')') + ")" : ""), off + 1, 1);
                ushort calc = U.Csum(d, off, end - off);
                c.N(n, "Checksum: " + U.Hx(csum, 4) + (calc == 0 ? " [correct]" : " [incorrect]"), off + 2, 2);
                c.N(n, "[Checksum Status: " + (calc == 0 ? "Good" : "Bad") + "]", off + 2, 2);
                if (t == 0 || t == 8)
                {
                    int id = U.W(d, off + 4), sq = U.W(d, off + 6);
                    c.N(n, "Identifier (BE): " + id + " (" + U.Hx(id, 4) + ")", off + 4, 2);
                    c.N(n, "Identifier (LE): " + (((id & 0xFF) << 8) | (id >> 8)) + " (" + U.Hx(((id & 0xFF) << 8) | (id >> 8), 4) + ")", off + 4, 2);
                    c.N(n, "Sequence Number (BE): " + sq + " (" + U.Hx(sq, 4) + ")", off + 6, 2);
                    c.N(n, "Sequence Number (LE): " + (((sq & 0xFF) << 8) | (sq >> 8)) + " (" + U.Hx(((sq & 0xFF) << 8) | (sq >> 8), 4) + ")", off + 6, 2);
                    if (end > off + 8) { TreeNode dn = c.N(n, "Data (" + (end - off - 8) + " bytes)", off + 8, end - off - 8); c.N(dn, "Data: " + U.HexStr(d, off + 8, end - off - 8), off + 8, end - off - 8); }
                }
            }
        }

        static void Igmp(Ctx c, int off, int end)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            c.Chain.Add("igmp");
            p.Protocol = "IGMP";
            int t = d[off];
            string grp = U.Ip4(d, off + 4);
            switch (t)
            {
                case 0x11:
                    p.Protocol = (end - off) >= 12 ? "IGMPv3" : "IGMPv2";
                    p.Info = "Membership Query, " + (grp == "0.0.0.0" ? "general" : "specific for group " + grp); break;
                case 0x12: p.Protocol = "IGMPv1"; p.Info = "Membership Report group " + grp; break;
                case 0x16: p.Protocol = "IGMPv2"; p.Info = "Membership Report group " + grp; break;
                case 0x17: p.Protocol = "IGMPv2"; p.Info = "Leave Group " + grp; break;
                case 0x22:
                    {
                        p.Protocol = "IGMPv3";
                        int n = U.W(d, off + 6), o = off + 8;
                        List<string> recs = new List<string>();
                        for (int i = 0; i < n && o + 8 <= end; i++)
                        {
                            int rt = d[o], aux = d[o + 1], ns = U.W(d, o + 2);
                            string g = U.Ip4(d, o + 4);
                            if (rt == 4 && ns == 0) recs.Add("Join group " + g + " for any sources");
                            else if (rt == 3 && ns == 0) recs.Add("Leave group " + g);
                            else if (rt == 2 && ns == 0) recs.Add("Group " + g + " for any sources");
                            else recs.Add("Group " + g + " (type " + rt + ", " + ns + " sources)");
                            o += 8 + ns * 4 + aux * 4;
                        }
                        p.Info = "Membership Report / " + string.Join(" / ", recs.ToArray());
                        break;
                    }
                default: p.Info = "IGMP type " + U.Hx(t, 2); break;
            }
            if (c.T)
            {
                TreeNode n = c.N(c.Root, "Internet Group Management Protocol", off, end - off);
                c.N(n, "[IGMP Version: " + (t == 0x22 ? 3 : t == 0x11 && end - off >= 12 ? 3 : 2) + "]", off, 1);
                c.N(n, "Type: " + p.Info.Split(new char[] { ',', ' ' })[0] + " (" + U.Hx(t, 2) + ")", off, 1);
                c.N(n, "Max Resp Time: " + (d[off + 1] / 10.0).ToString("0.0", CultureInfo.InvariantCulture) + " sec (" + U.Hx(d[off + 1], 2) + ")", off + 1, 1);
                c.N(n, "Checksum: " + U.Hx(U.W(d, off + 2), 4) + " [" + (U.Csum(d, off, end - off) == 0 ? "correct" : "incorrect") + "]", off + 2, 2);
                if (t != 0x22) c.N(n, "Multicast Address: " + grp, off + 4, 4);
            }
        }

        static void Icmp6(Ctx c, int off, int end)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            c.Chain.Add("icmpv6");
            p.Protocol = "ICMPv6";
            int t = d[off], code = d[off + 1], csum = U.W(d, off + 2);
            string name;
            string info;
            switch (t)
            {
                case 1: { string[] n = { "No route to destination", "Communication with destination administratively prohibited", "Beyond scope of source address", "Address unreachable", "Port unreachable" }; name = "Destination Unreachable"; info = name + " (" + (code < n.Length ? n[code] : "code " + code) + ")"; break; }
                case 2: name = "Packet Too Big"; info = name + " (MTU: " + U.L(d, off + 4) + ")"; break;
                case 3: name = "Time Exceeded"; info = name + " (" + (code == 0 ? "hop limit exceeded in transit" : "fragment reassembly time exceeded") + ")"; break;
                case 128:
                case 129:
                    {
                        name = t == 128 ? "Echo (ping) request" : "Echo (ping) reply";
                        int hl = p.Ttl;
                        info = name + " id=" + U.Hx(U.W(d, off + 4), 4) + ", seq=" + U.W(d, off + 6) + ", hop limit=" + hl;
                        break;
                    }
                case 130: name = "Multicast Listener Query"; info = name; break;
                case 131: name = "Multicast Listener Report"; info = name; break;
                case 132: name = "Multicast Listener Done"; info = name; break;
                case 133: name = "Router Solicitation"; info = name + LlOpt(d, off + 8, end, 1); break;
                case 134: name = "Router Advertisement"; info = name + LlOpt(d, off + 16, end, 1); break;
                case 135: name = "Neighbor Solicitation"; info = name + " for " + U.Ip6(d, off + 8) + LlOpt(d, off + 24, end, 1); break;
                case 136:
                    {
                        name = "Neighbor Advertisement";
                        uint fl = U.L(d, off + 4);
                        List<string> f = new List<string>();
                        if ((fl & 0x80000000) != 0) f.Add("rtr");
                        if ((fl & 0x40000000) != 0) f.Add("sol");
                        if ((fl & 0x20000000) != 0) f.Add("ovr");
                        string at = LlOpt(d, off + 24, end, 2);
                        info = name + " " + U.Ip6(d, off + 8) + " (" + string.Join(", ", f.ToArray()) + ")" + (at.Length > 0 ? " is at " + at.Substring(6) : "");
                        break;
                    }
                case 143: name = "Multicast Listener Report Message v2"; info = name; break;
                default: name = "Type " + t; info = name; break;
            }
            p.Info = info;
            if (c.T)
            {
                TreeNode n = c.N(c.Root, "Internet Control Message Protocol v6", off, end - off);
                c.N(n, "Type: " + name + " (" + t + ")", off, 1);
                c.N(n, "Code: " + code, off + 1, 1);
                c.N(n, "Checksum: " + U.Hx(csum, 4) + " [unverified]", off + 2, 2);
                c.N(n, "[Checksum Status: Unverified]", off + 2, 2);
                if (t == 128 || t == 129)
                {
                    c.N(n, "Identifier: " + U.Hx(U.W(d, off + 4), 4), off + 4, 2);
                    c.N(n, "Sequence: " + U.W(d, off + 6), off + 6, 2);
                }
                else if (t == 135 || t == 136) c.N(n, "Target Address: " + U.Ip6(d, off + 8), off + 8, 16);
            }
        }

        // " from aa:bb:.." (source LL option, kind 1) or " at aa:bb:.." (target LL, kind 2) from ND options
        static string LlOpt(byte[] d, int o, int end, int kind)
        {
            while (o + 2 <= end && o + 2 <= d.Length)
            {
                int k = d[o], l = d[o + 1] * 8;
                if (l == 0) break;
                if (k == kind && o + 8 <= d.Length) return (kind == 1 ? " from " : " at   ") + U.Mac(d, o + 2);
                o += l;
            }
            return "";
        }

        // ----------------------------------------------------------------- UDP
        static void Udp(Ctx c, int off, int end)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            c.Chain.Add("udp");
            int sport = U.W(d, off), dport = U.W(d, off + 2), ulen = U.W(d, off + 4), csum = U.W(d, off + 6);
            p.SrcPort = sport; p.DstPort = dport;
            p.Protocol = "UDP";
            p.Info = sport + " " + U.Arrow + " " + dport + " Len=" + Math.Max(0, ulen - 8);
            int poff = off + 8;
            int pend = (ulen >= 8) ? Math.Min(off + ulen, end) : end;
            p.PayOff = poff; p.PayEnd = pend;
            if (c.T)
            {
                TreeNode u = c.N(c.Root, "User Datagram Protocol, Src Port: " + sport + ", Dst Port: " + dport, off, 8);
                c.N(u, "Source Port: " + sport, off, 2);
                c.N(u, "Destination Port: " + dport, off + 2, 2);
                c.N(u, "Length: " + ulen, off + 4, 2);
                c.N(u, "Checksum: " + U.Hx(csum, 4) + " [unverified]", off + 6, 2);
                c.N(u, "[Checksum Status: Unverified]", off + 6, 2);
                if (pend > poff) c.N(u, "UDP payload (" + (pend - poff) + " bytes)", poff, pend - poff);
            }
            if (pend <= poff) return;
            if (sport == 53 || dport == 53) { if (Dns(c, poff, pend, "DNS")) return; }
            else if (sport == 5353 || dport == 5353) { if (Dns(c, poff, pend, "MDNS")) return; }
            else if (sport == 5355 || dport == 5355) { if (Dns(c, poff, pend, "LLMNR")) return; }
            else if ((sport == 67 || sport == 68) && (dport == 67 || dport == 68)) { if (Dhcp(c, poff, pend)) return; }
            else if (sport == 1900 || dport == 1900) { if (Ssdp(c, poff, pend)) return; }
            else if (sport == 123 || dport == 123) { if (Ntp(c, poff, pend)) return; }
            Payload(c, poff, pend, "Data");
        }

        // ----------------------------------------------------------------- TCP
        internal class TcpOpts
        {
            public List<OptEntry> E = new List<OptEntry>();
            public int Ws = -1;
        }

        internal static TcpOpts ScanOpts(byte[] d, int o, int oe)
        {
            TcpOpts t = new TcpOpts();
            oe = Math.Min(oe, d.Length);
            while (o < oe)
            {
                int k = d[o];
                OptEntry e = new OptEntry(); e.Kind = k; e.Start = o;
                if (k == 0 || k == 1) { e.Len = 1; t.E.Add(e); o++; if (k == 0) break; continue; }
                if (o + 1 >= oe) break;
                int l = d[o + 1];
                if (l < 2 || o + l > oe) break;
                e.Len = l; t.E.Add(e);
                if (k == 3 && l >= 3) t.Ws = d[o + 2];
                o += l;
            }
            return t;
        }

        static string TcpFlagsStr(int f)
        {
            string[] n = { "FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "AE" };
            List<string> l = new List<string>();
            for (int i = 0; i < 9; i++) if ((f & (1 << i)) != 0) l.Add(n[i]);
            return l.Count == 0 ? "<None>" : string.Join(", ", l.ToArray());
        }

        TcpStream Track(Packet p, uint seq, uint ack, int flags, int win, int len, TcpOpts o, out int dir)
        {
            string a = p.SrcIp + ":" + p.SrcPort, b = p.DstIp + ":" + p.DstPort;
            dir = string.CompareOrdinal(a, b) <= 0 ? 0 : 1;
            string key = dir == 0 ? a + "|" + b : b + "|" + a;
            TcpStream s;
            if (!streams.TryGetValue(key, out s)) { s = new TcpStream(); s.Index = nextStream++; streams[key] = s; }
            p.StreamIdx = s.Index;
            bool syn = (flags & 2) != 0, fin = (flags & 1) != 0, ackf = (flags & 0x10) != 0;
            int od = 1 - dir;
            if (!s.Has[dir]) { s.Base[dir] = syn ? seq : seq - 1; s.Has[dir] = true; }
            p.RelSeq = seq - s.Base[dir];
            if (s.Has[od]) { p.RelAck = ack - s.Base[od]; p.OppBase = s.Base[od]; p.HasOpp = true; }
            else { p.RelAck = 1; p.OppBase = ack - 1; p.HasOpp = false; }
            if (syn) s.Ws[dir] = o.Ws >= 0 ? o.Ws : -1;
            p.WinScale = (!syn && s.Ws[0] >= 0 && s.Ws[1] >= 0) ? s.Ws[dir] : -1;
            uint segEnd = seq + (uint)len + (syn ? 1u : 0u) + (fin ? 1u : 0u);
            bool ka = false;
            if (len <= 1 && s.HasNext[dir] && (flags & 0x07) == 0 && ackf && (uint)(seq + 1) == s.Next[dir])
            { ka = true; p.TcpNote = "TCP Keep-Alive"; s.LastKa = dir; }
            else if (len == 0 && (flags & 0x17) == 0x10 && s.LastKa == od && s.HasNext[dir] && seq == s.Next[dir])
            { p.TcpNote = "TCP Keep-Alive ACK"; s.LastKa = -1; }
            else
            {
                s.LastKa = -1;
                if (len > 0 && s.HasNext[dir] && (int)(seq - s.Next[dir]) < 0) p.TcpNote = "TCP Retransmission";
                else if (len > 0 && s.HasNext[dir] && (int)(seq - s.Next[dir]) > 0) p.TcpNote = "TCP Previous segment not captured";
            }
            if (!ka && (!s.HasNext[dir] || (int)(segEnd - s.Next[dir]) > 0)) { s.Next[dir] = segEnd; s.HasNext[dir] = true; }
            return s;
        }

        static string OptName(int k)
        {
            switch (k)
            {
                case 0: return "End of Option List (EOL)"; case 1: return "No-Operation (NOP)"; case 2: return "Maximum segment size";
                case 3: return "Window scale"; case 4: return "SACK permitted"; case 5: return "SACK"; case 8: return "Timestamps";
                default: return "Unknown (" + k + ")";
            }
        }

        static void Tcp(Ctx c, int off, int end)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            c.Chain.Add("tcp");
            int sport = U.W(d, off), dport = U.W(d, off + 2);
            uint seq = U.L(d, off + 4), ack = U.L(d, off + 8);
            int hlen = (d[off + 12] >> 4) * 4;
            int flags = ((d[off + 12] & 1) << 8) | d[off + 13];
            int win = U.W(d, off + 14), csum = U.W(d, off + 16), urg = U.W(d, off + 18);
            int poff = off + hlen;
            int len = Math.Max(0, end - poff);
            p.PayOff = poff; p.PayEnd = end;
            p.SrcPort = sport; p.DstPort = dport;
            p.Protocol = "TCP";
            TcpOpts opts = ScanOpts(d, off + 20, off + hlen);
            TcpStream s = null; int dir = 0;
            if (!c.T) s = c.D.Track(p, seq, ack, flags, win, len, opts, out dir);

            // ---- Info
            uint calcWin = p.WinScale >= 0 ? (uint)win << p.WinScale : (uint)win;
            StringBuilder inf = new StringBuilder();
            if (p.TcpNote != null) inf.Append("[" + p.TcpNote + "] ");
            inf.Append(sport + " " + U.Arrow + " " + dport + " [" + TcpFlagsStr(flags) + "] Seq=" + p.RelSeq);
            if ((flags & 0x10) != 0) inf.Append(" Ack=" + p.RelAck);
            inf.Append(" Win=" + calcWin + " Len=" + len);
            foreach (OptEntry e in opts.E)
            {
                int o = e.Start;
                if (e.Kind == 2) inf.Append(" MSS=" + U.W(d, o + 2));
                else if (e.Kind == 3) inf.Append(" WS=" + (1 << d[o + 2]));
                else if (e.Kind == 4) inf.Append(" SACK_PERM");
                else if (e.Kind == 8) inf.Append(" TSval=" + U.L(d, o + 2) + " TSecr=" + U.L(d, o + 6));
                else if (e.Kind == 5)
                    for (int b = 0; b + 8 <= e.Len - 2; b += 8)
                        inf.Append(" SLE=" + (U.L(d, o + 2 + b) - p.OppBase) + " SRE=" + (U.L(d, o + 6 + b) - p.OppBase));
            }
            p.Info = inf.ToString();

            // ---- reassembly (stateful pass; the tree pass reads the result stored in the packet)
            if (!c.T && s != null)
            {
                if (len > 0 && (p.TcpNote == null || p.TcpNote == "TCP Retransmission" || p.TcpNote == "TCP Previous segment not captured")) Reassemble(c, s, dir, seq, poff, end);
                if ((flags & 0x05) != 0 && s.R[dir] != null) s.R[dir].Reset();      // FIN / RST ends any pending PDU
            }
            int uend = p.DEnd > 0 ? p.DEnd : end;
            bool handledR = p.ReasmData != null;
            bool plainSeg = p.SegOfPdu && p.DEnd <= 0 && !handledR;

            // ---- upper layer
            bool skipUpper = p.TcpNote == "TCP Retransmission" && !handledR;
            bool http = false, tls = false;
            if (len > 0 && !skipUpper && !handledR && !plainSeg)
            {
                http = LooksHttp(d, poff, uend);
                if (!http)
                {
                    bool encNow = c.T ? p.TlsEncStart : (s != null && s.Enc[dir]);
                    tls = LooksTls(d, poff, uend, encNow) || (c.T ? p.TlsProto != null : (s != null && s.Tls));
                }
            }

            // ---- tree
            if (c.T)
            {
                TreeNode t = c.N(c.Root, "Transmission Control Protocol, Src Port: " + sport + ", Dst Port: " + dport + ", Seq: " + p.RelSeq + (((flags & 0x10) != 0) ? ", Ack: " + p.RelAck : "") + ", Len: " + len, off, hlen);
                c.N(t, "Source Port: " + sport, off, 2);
                c.N(t, "Destination Port: " + dport, off + 2, 2);
                c.N(t, "[Stream index: " + p.StreamIdx + "]", off, 0);
                c.N(t, "[TCP Segment Len: " + len + "]", off + 12, 1);
                c.N(t, "Sequence Number: " + p.RelSeq + "    (relative sequence number)", off + 4, 4);
                c.N(t, "Sequence Number (raw): " + seq, off + 4, 4);
                bool syn = (flags & 2) != 0, fin = (flags & 1) != 0;
                uint next = p.RelSeq + (uint)len + (syn ? 1u : 0u) + (fin ? 1u : 0u);
                c.N(t, "[Next Sequence Number: " + next + "    (relative sequence number)]", off + 4, 4);
                c.N(t, "Acknowledgment Number: " + ((flags & 0x10) != 0 ? p.RelAck : 0) + ((flags & 0x10) != 0 ? "    (relative ack number)" : ""), off + 8, 4);
                c.N(t, "Acknowledgment number (raw): " + ack, off + 8, 4);
                c.N(t, U.Bits(8, 0xF0, (uint)d[off + 12]) + " = Header Length: " + hlen + " bytes (" + (hlen / 4) + ")", off + 12, 1);
                string fs = TcpFlagsStr(flags);
                TreeNode f = c.N(t, "Flags: " + U.Hx(flags, 3) + " (" + fs + ")", off + 12, 2);
                uint fv = (uint)flags;
                c.N(f, U.Bits(12, 0xE00, fv) + " = Reserved: Not set", off + 12, 1);
                c.N(f, U.Bits(12, 0x100, fv) + " = Accurate ECN: " + ((flags & 0x100) != 0 ? "Set" : "Not set"), off + 12, 1);
                c.N(f, U.Bits(12, 0x080, fv) + " = Congestion Window Reduced: " + ((flags & 0x80) != 0 ? "Set" : "Not set"), off + 13, 1);
                c.N(f, U.Bits(12, 0x040, fv) + " = ECN-Echo: " + ((flags & 0x40) != 0 ? "Set" : "Not set"), off + 13, 1);
                c.N(f, U.Bits(12, 0x020, fv) + " = Urgent: " + ((flags & 0x20) != 0 ? "Set" : "Not set"), off + 13, 1);
                c.N(f, U.Bits(12, 0x010, fv) + " = Acknowledgment: " + ((flags & 0x10) != 0 ? "Set" : "Not set"), off + 13, 1);
                c.N(f, U.Bits(12, 0x008, fv) + " = Push: " + ((flags & 0x08) != 0 ? "Set" : "Not set"), off + 13, 1);
                c.N(f, U.Bits(12, 0x004, fv) + " = Reset: " + ((flags & 0x04) != 0 ? "Set" : "Not set"), off + 13, 1);
                c.N(f, U.Bits(12, 0x002, fv) + " = Syn: " + ((flags & 0x02) != 0 ? "Set" : "Not set"), off + 13, 1);
                c.N(f, U.Bits(12, 0x001, fv) + " = Fin: " + ((flags & 0x01) != 0 ? "Set" : "Not set"), off + 13, 1);
                char[] fc = new char[12];
                for (int i = 0; i < 12; i++) fc[i] = '\u00B7';
                string letters = "NCEUAPRSF";
                for (int i = 0; i < 9; i++) if ((flags & (1 << (8 - i))) != 0) fc[3 + i] = letters[i];
                c.N(f, "[TCP Flags: " + new string(fc) + "]", off + 12, 2);
                c.N(t, "Window: " + win, off + 14, 2);
                if (p.WinScale >= 0)
                {
                    c.N(t, "[Calculated window size: " + calcWin + "]", off + 14, 2);
                    c.N(t, "[Window size scaling factor: " + (1 << p.WinScale) + "]", off + 14, 2);
                }
                else if (!syn) c.N(t, "[Window size scaling factor: -1 (unknown)]", off + 14, 2);
                c.N(t, "Checksum: " + U.Hx(csum, 4) + " [unverified]", off + 16, 2);
                c.N(t, "[Checksum Status: Unverified]", off + 16, 2);
                c.N(t, "Urgent Pointer: " + urg, off + 18, 2);
                if (hlen > 20 && opts.E.Count > 0)
                {
                    List<string> names = new List<string>();
                    TreeNode tmp = new TreeNode("", 0, 0);
                    foreach (OptEntry e in opts.E)
                    {
                        names.Add(OptName(e.Kind));
                        TreeNode on;
                        int o = e.Start;
                        switch (e.Kind)
                        {
                            case 2:
                                on = c.N(tmp, "TCP Option - Maximum segment size: " + U.W(d, o + 2) + " bytes", o, e.Len);
                                c.N(on, "Kind: Maximum Segment Size (2)", o, 1); c.N(on, "Length: 4", o + 1, 1); c.N(on, "MSS Value: " + U.W(d, o + 2), o + 2, 2); break;
                            case 3:
                                on = c.N(tmp, "TCP Option - Window scale: " + d[o + 2] + " (multiply by " + (1 << d[o + 2]) + ")", o, e.Len);
                                c.N(on, "Kind: Window Scale (3)", o, 1); c.N(on, "Length: 3", o + 1, 1); c.N(on, "Shift count: " + d[o + 2], o + 2, 1); c.N(on, "[Multiplier: " + (1 << d[o + 2]) + "]", o + 2, 1); break;
                            case 4:
                                on = c.N(tmp, "TCP Option - SACK permitted", o, e.Len);
                                c.N(on, "Kind: SACK Permitted (4)", o, 1); c.N(on, "Length: 2", o + 1, 1); break;
                            case 5:
                                {
                                    int nb = (e.Len - 2) / 8;
                                    StringBuilder sb = new StringBuilder();
                                    for (int b = 0; b < nb; b++) sb.Append(" " + (U.L(d, o + 2 + b * 8) - p.OppBase) + "-" + (U.L(d, o + 6 + b * 8) - p.OppBase));
                                    on = c.N(tmp, "TCP Option - SACK" + sb.ToString(), o, e.Len);
                                    c.N(on, "Kind: SACK (5)", o, 1); c.N(on, "Length: " + e.Len, o + 1, 1);
                                    for (int b = 0; b < nb; b++)
                                    {
                                        c.N(on, "left edge = " + (U.L(d, o + 2 + b * 8) - p.OppBase) + "    (relative)", o + 2 + b * 8, 4);
                                        c.N(on, "right edge = " + (U.L(d, o + 6 + b * 8) - p.OppBase) + "    (relative)", o + 6 + b * 8, 4);
                                    }
                                    c.N(on, "[TCP SACK Count: " + nb + "]", o, e.Len);
                                    break;
                                }
                            case 8:
                                on = c.N(tmp, "TCP Option - Timestamps: TSval " + U.L(d, o + 2) + ", TSecr " + U.L(d, o + 6), o, e.Len);
                                c.N(on, "Kind: Time Stamp Option (8)", o, 1); c.N(on, "Length: 10", o + 1, 1);
                                c.N(on, "Timestamp value: " + U.L(d, o + 2), o + 2, 4); c.N(on, "Timestamp echo reply: " + U.L(d, o + 6), o + 6, 4); break;
                            default:
                                on = c.N(tmp, "TCP Option - " + OptName(e.Kind), o, e.Len);
                                c.N(on, "Kind: " + OptName(e.Kind).Split(' ')[0] + " (" + e.Kind + ")", o, 1); break;
                        }
                    }
                    TreeNode optNode = c.N(t, "Options: (" + (hlen - 20) + " bytes), " + string.Join(", ", names.ToArray()), off + 20, hlen - 20);
                    optNode.Children = tmp.Children;
                }
                if (p.TcpNote != null)
                {
                    TreeNode sa = c.N(t, "[SEQ/ACK analysis]", off, 0);
                    TreeNode an = c.N(sa, "[TCP Analysis Flags]", off, 0);
                    c.N(an, "[Expert Info (Note/Sequence): " + p.TcpNote.Replace("TCP ", "") + "]", off, 0);
                }
                if (len > 0) c.N(t, "TCP payload (" + len + " bytes)", poff, len);
                if (p.ReasmData != null)
                {
                    List<string> rp = new List<string>();
                    for (int i = 0; i < p.ReasmNos.Length; i++) rp.Add("#" + p.ReasmNos[i] + "(" + p.ReasmLens[i] + ")");
                    TreeNode rn = c.N(t, "[" + p.ReasmNos.Length + " Reassembled TCP Segments (" + p.ReasmPduLen + " bytes): " + string.Join(", ", rp.ToArray()) + "]", poff, len);
                    int rpos = 0;
                    for (int i = 0; i < p.ReasmNos.Length; i++)
                    {
                        c.N(rn, "[Frame: " + p.ReasmNos[i] + ", payload: " + rpos + "-" + (rpos + p.ReasmLens[i] - 1) + " (" + p.ReasmLens[i] + " bytes)]", poff, 0);
                        rpos += p.ReasmLens[i];
                    }
                }
                else if (p.SegOfPdu)
                {
                    if (p.ReasmIn > 0) c.N(t, "[Reassembled PDU in frame: " + p.ReasmIn + "]", poff, 0);
                    else c.N(t, "[TCP segment of a reassembled PDU]", poff, 0);
                }
            }

            if (len <= 0 || skipUpper) return;
            if (handledR) { if (c.T) DissectAssembled(c, null, 0); return; }
            if (plainSeg) { Payload(c, poff, end, "TCP segment data"); return; }
            if (http) { HttpMulti(c, poff, uend); return; }
            if (tls) { Tls(c, poff, uend, s, dir); return; }
            if ((sport == 53 || dport == 53) && len >= 14)
            {
                // DNS over TCP: 2-byte length prefix, then the DNS message
                int mend = Math.Min(uend, poff + 2 + U.W(d, poff));
                if (Dns(c, poff + 2, mend, "DNS")) return;
            }
            Payload(c, poff, uend, "Data");
        }
    }
}

namespace PSShark
{
    public partial class Dissector
    {
        // ----------------------------------------------------------------- DNS
        static string DnsType(int t)
        {
            switch (t)
            {
                case 1: return "A"; case 2: return "NS"; case 5: return "CNAME"; case 6: return "SOA"; case 12: return "PTR";
                case 15: return "MX"; case 16: return "TXT"; case 28: return "AAAA"; case 33: return "SRV"; case 41: return "OPT";
                case 65: return "HTTPS"; case 255: return "ANY"; default: return "Type " + t;
            }
        }
        static string DnsTypeLong(int t)
        {
            switch (t)
            {
                case 1: return "A (Host Address)"; case 2: return "NS (Authoritative Name Server)"; case 5: return "CNAME (Canonical NAME for an alias)";
                case 6: return "SOA (Start Of a zone of Authority)"; case 12: return "PTR (domain name PoinTeR)"; case 15: return "MX (Mail eXchange)";
                case 16: return "TXT (Text strings)"; case 28: return "AAAA (IPv6 Address)"; case 33: return "SRV (Server Selection)";
                case 41: return "OPT (Option)"; case 65: return "HTTPS (HTTPS Specific Service Endpoints)"; case 255: return "ANY (request for all records)";
                default: return DnsType(t);
            }
        }

        static string DnsName(byte[] d, int msg, ref int pos, int end)
        {
            StringBuilder sb = new StringBuilder();
            int p = pos, after = -1, guard = 0;
            while (guard++ < 128)
            {
                int l = d[p];
                if (l == 0) { p++; break; }
                if ((l & 0xC0) == 0xC0)
                {
                    int ptr = ((l & 0x3F) << 8) | d[p + 1];
                    if (after < 0) after = p + 2;
                    p = msg + ptr;
                    continue;
                }
                p++;
                sb.Append(Encoding.ASCII.GetString(d, p, l)).Append('.');
                p += l;
            }
            pos = after >= 0 ? after : p;
            if (sb.Length == 0) return "<Root>";
            return sb.ToString(0, sb.Length - 1);
        }

        class DnsRr { public string Name; public int Type, Class, Start, Len, RdStart, RdLen; public uint Ttl; public string Data, Short, Desc; }

        static DnsRr ReadRr(byte[] d, int msg, ref int pos, int end, bool question)
        {
            DnsRr r = new DnsRr();
            r.Start = pos;
            r.Name = DnsName(d, msg, ref pos, end);
            r.Type = U.W(d, pos); r.Class = U.W(d, pos + 2);
            pos += 4;
            if (question) { r.Len = pos - r.Start; return r; }
            r.Ttl = U.L(d, pos); r.RdLen = U.W(d, pos + 4); pos += 6;
            r.RdStart = pos;
            int rp = pos;
            switch (r.Type)
            {
                case 1: r.Data = U.Ip4(d, rp); r.Short = r.Data; r.Desc = "addr " + r.Data; break;
                case 28: r.Data = U.Ip6(d, rp); r.Short = r.Data; r.Desc = "addr " + r.Data; break;
                case 2: { string n = DnsName(d, msg, ref rp, end); r.Data = n; r.Short = n; r.Desc = "ns " + n; break; }
                case 5: { string n = DnsName(d, msg, ref rp, end); r.Data = n; r.Short = n; r.Desc = "cname " + n; break; }
                case 12: { string n = DnsName(d, msg, ref rp, end); r.Data = n; r.Short = n; r.Desc = "domain name " + n; break; }
                case 15: { int pref = U.W(d, rp); rp += 2; string n = DnsName(d, msg, ref rp, end); r.Data = n; r.Short = pref + " " + n; r.Desc = "preference " + pref + ", mx " + n; break; }
                case 6: { string m = DnsName(d, msg, ref rp, end); string rn = DnsName(d, msg, ref rp, end); r.Data = m; r.Short = m + " " + rn; r.Desc = "mname " + m; break; }
                case 33: { int pr = U.W(d, rp), w = U.W(d, rp + 2), po = U.W(d, rp + 4); rp += 6; string n = DnsName(d, msg, ref rp, end); r.Data = n; r.Short = pr + " " + w + " " + po + " " + n; r.Desc = "priority " + pr + ", weight " + w + ", port " + po + ", target " + n; break; }
                case 16: { int tl = d[rp]; string tx = Encoding.ASCII.GetString(d, rp + 1, Math.Min(tl, d.Length - rp - 1)); r.Data = tx; r.Short = ""; r.Desc = "TXT"; break; }
                default: r.Data = ""; r.Short = ""; r.Desc = "data"; break;
            }
            pos += r.RdLen;
            r.Len = pos - r.Start;
            return r;
        }

        static string DnsRcode(int rc)
        {
            switch (rc) { case 1: return "Format error"; case 2: return "Server failure"; case 3: return "No such name"; case 4: return "Not implemented"; case 5: return "Refused"; default: return ""; }
        }

        static bool Dns(Ctx c, int off, int end, string proto)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            if (end - off < 12) return false;
            bool mdns = proto == "MDNS";
            int id = U.W(d, off), fl = U.W(d, off + 2), qd = U.W(d, off + 4), an = U.W(d, off + 6), ns = U.W(d, off + 8), ar = U.W(d, off + 10);
            bool resp = (fl & 0x8000) != 0;
            int opcode = (fl >> 11) & 0xF, rcode = fl & 0xF;
            if (qd > 64 || an > 256 || ns > 256 || ar > 256) return false;
            int pos = off + 12;
            List<DnsRr> qs = new List<DnsRr>(), ans = new List<DnsRr>(), auths = new List<DnsRr>(), adds = new List<DnsRr>();
            try
            {
                for (int i = 0; i < qd; i++) qs.Add(ReadRr(d, off, ref pos, end, true));
                for (int i = 0; i < an; i++) ans.Add(ReadRr(d, off, ref pos, end, false));
                for (int i = 0; i < ns; i++) auths.Add(ReadRr(d, off, ref pos, end, false));
                for (int i = 0; i < ar; i++) adds.Add(ReadRr(d, off, ref pos, end, false));
            }
            catch (IndexOutOfRangeException) { }
            catch (ArgumentException) { }

            c.Chain.Add(proto.ToLowerInvariant());
            p.Protocol = proto;
            string opn = opcode == 0 ? "Standard query" : opcode == 1 ? "Inverse query" : opcode == 2 ? "Server status request" : opcode == 4 ? "Notify" : opcode == 5 ? "Dynamic update" : "Opcode " + opcode;
            StringBuilder inf = new StringBuilder();
            inf.Append(opn + (resp ? " response" : "") + " " + U.Hx(id, 4));
            if (resp && DnsRcode(rcode).Length > 0) inf.Append(" " + DnsRcode(rcode));
            List<string> qtxt = new List<string>();
            foreach (DnsRr q in qs)
            {
                if (mdns) qtxt.Add(DnsType(q.Type) + " " + q.Name + ", \"" + ((q.Class & 0x8000) != 0 ? "QU" : "QM") + "\" question");
                else qtxt.Add(DnsType(q.Type) + " " + q.Name);
            }
            if (qtxt.Count > 0) inf.Append(" " + string.Join(mdns ? ", " : " ", qtxt.ToArray()));
            List<string> atxt = new List<string>();
            foreach (DnsRr r in ans) atxt.Add(DnsType(r.Type) + (mdns && (r.Class & 0x8000) != 0 ? ", cache flush" : "") + (r.Short != null && r.Short.Length > 0 ? " " + r.Short : ""));
            foreach (DnsRr r in auths) atxt.Add(DnsType(r.Type) + (r.Short != null && r.Short.Length > 0 ? " " + r.Short : ""));
            foreach (DnsRr r in adds) if (r.Type == 41) atxt.Add("OPT");
            if (atxt.Count > 0) inf.Append(" " + string.Join(mdns ? ", " : " ", atxt.ToArray()));
            p.Info = inf.ToString();

            if (!c.T)
            {
                p.AddApp("dns.id", (long)id);
                p.AddApp("dns.flags.response", resp ? 1L : 0L);
                p.AddApp("dns.flags.opcode", (long)opcode);
                p.AddApp("dns.flags.authoritative", (fl & 0x400) != 0 ? 1L : 0L);
                p.AddApp("dns.flags.truncated", (fl & 0x200) != 0 ? 1L : 0L);
                p.AddApp("dns.flags.recdesired", (fl & 0x100) != 0 ? 1L : 0L);
                p.AddApp("dns.flags.recavail", (fl & 0x80) != 0 ? 1L : 0L);
                p.AddApp("dns.flags.rcode", (long)rcode);
                p.AddApp("dns.count.queries", (long)qd); p.AddApp("dns.count.answers", (long)an);
                p.AddApp("dns.count.auth_rr", (long)ns); p.AddApp("dns.count.add_rr", (long)ar);
                foreach (DnsRr q in qs) { p.AddApp("dns.qry.name", q.Name); p.AddApp("dns.qry.type", (long)q.Type); p.AddApp("dns.qry.class", (long)(q.Class & 0x7FFF)); }
                List<DnsRr> allRr = new List<DnsRr>(ans); allRr.AddRange(auths); allRr.AddRange(adds);
                foreach (DnsRr r in allRr)
                {
                    p.AddApp("dns.resp.name", r.Name); p.AddApp("dns.resp.type", (long)r.Type);
                    p.AddApp("dns.resp.class", (long)(r.Class & 0x7FFF)); p.AddApp("dns.resp.ttl", (long)r.Ttl);
                    switch (r.Type)
                    {
                        case 1: if (r.RdLen == 4) p.AddApp("dns.a", (long)U.L(d, r.RdStart)); break;
                        case 28: if (r.RdLen == 16) { byte[] b6 = new byte[16]; Array.Copy(d, r.RdStart, b6, 0, 16); p.AddApp("dns.aaaa", b6); } break;
                        case 5: p.AddApp("dns.cname", r.Data); break;
                        case 2: p.AddApp("dns.ns", r.Data); break;
                        case 12: p.AddApp("dns.ptr.domain_name", r.Data); break;
                        case 15: p.AddApp("dns.mx.mail_exchange", r.Data); break;
                    }
                }
            }

            if (c.T)
            {
                TreeNode t = c.N(c.Root, (proto == "MDNS" ? "Multicast Domain Name System" : proto == "LLMNR" ? "Link-local Multicast Name Resolution" : "Domain Name System") + " (" + (resp ? "response" : "query") + ")", off, end - off);
                if (off >= 2 && (":" + p.Chain + ":").IndexOf(":tcp:") >= 0) c.N(t, "Length: " + U.W(d, off - 2), off - 2, 2);
                c.N(t, "Transaction ID: " + U.Hx(id, 4), off, 2);
                TreeNode f = c.N(t, "Flags: " + U.Hx(fl, 4) + " " + opn + (resp ? " response" : ""), off + 2, 2);
                uint fv = (uint)fl;
                c.N(f, U.Bits(16, 0x8000, fv) + " = Response: Message is a " + (resp ? "response" : "query"), off + 2, 2);
                c.N(f, U.Bits(16, 0x7800, fv) + " = Opcode: " + opn + " (" + opcode + ")", off + 2, 2);
                if (resp) c.N(f, U.Bits(16, 0x0400, fv) + " = Authoritative: Server is " + ((fl & 0x400) != 0 ? "" : "not ") + "an authority for domain", off + 2, 2);
                c.N(f, U.Bits(16, 0x0200, fv) + " = Truncated: Message is " + ((fl & 0x200) != 0 ? "" : "not ") + "truncated", off + 2, 2);
                c.N(f, U.Bits(16, 0x0100, fv) + " = Recursion desired: " + ((fl & 0x100) != 0 ? "Do query recursively" : "Don't do query recursively"), off + 2, 2);
                if (resp) c.N(f, U.Bits(16, 0x0080, fv) + " = Recursion available: Server can" + ((fl & 0x80) != 0 ? "" : "'t") + " do recursive queries", off + 2, 2);
                c.N(f, U.Bits(16, 0x0040, fv) + " = Z: reserved (0)", off + 2, 2);
                if (resp) c.N(f, U.Bits(16, 0x000F, fv) + " = Reply code: " + (rcode == 0 ? "No error" : DnsRcode(rcode)) + " (" + rcode + ")", off + 2, 2);
                c.N(t, "Questions: " + qd, off + 4, 2);
                c.N(t, "Answer RRs: " + an, off + 6, 2);
                c.N(t, "Authority RRs: " + ns, off + 8, 2);
                c.N(t, "Additional RRs: " + ar, off + 10, 2);
                if (qs.Count > 0)
                {
                    int qs0 = qs[0].Start, ql = qs[qs.Count - 1].Start + qs[qs.Count - 1].Len - qs0;
                    TreeNode qn = c.N(t, "Queries", qs0, ql);
                    foreach (DnsRr q in qs)
                    {
                        TreeNode e = c.N(qn, q.Name + ": type " + DnsType(q.Type) + ", class " + ((q.Class & 0x7FFF) == 1 ? "IN" : "0x" + (q.Class & 0x7FFF).ToString("x4")), q.Start, q.Len);
                        c.N(e, "Name: " + q.Name, q.Start, q.Len - 4);
                        c.N(e, "[Name Length: " + (q.Name == "<Root>" ? 0 : q.Name.Length) + "]", q.Start, q.Len - 4);
                        c.N(e, "[Label Count: " + (q.Name == "<Root>" ? 0 : q.Name.Split('.').Length) + "]", q.Start, q.Len - 4);
                        c.N(e, "Type: " + DnsTypeLong(q.Type) + " (" + q.Type + ")", q.Start + q.Len - 4, 2);
                        c.N(e, "Class: " + ((q.Class & 0x7FFF) == 1 ? "IN" : "0x" + (q.Class & 0x7FFF).ToString("x4")) + " (" + U.Hx(q.Class & 0x7FFF, 4) + ")", q.Start + q.Len - 2, 2);
                    }
                }
                RrSection(c, t, "Answers", ans, mdns);
                RrSection(c, t, "Authoritative nameservers", auths, mdns);
                RrSection(c, t, "Additional records", adds, mdns);
            }
            return true;
        }

        static void RrSection(Ctx c, TreeNode t, string title, List<DnsRr> rrs, bool mdns)
        {
            if (rrs.Count == 0) return;
            int s0 = rrs[0].Start, l = rrs[rrs.Count - 1].Start + rrs[rrs.Count - 1].Len - s0;
            TreeNode sec = c.N(t, title, s0, l);
            foreach (DnsRr r in rrs)
            {
                string cls = (r.Class & 0x7FFF) == 1 ? "IN" : "0x" + (r.Class & 0x7FFF).ToString("x4");
                TreeNode e = c.N(sec, r.Name + ": type " + DnsType(r.Type) + ", class " + cls + (mdns && (r.Class & 0x8000) != 0 ? ", cache flush" : "") + (r.Type == 41 ? "" : ", " + r.Desc), r.Start, r.Len);
                int nl = r.Len - 10 - r.RdLen;
                c.N(e, "Name: " + r.Name, r.Start, nl);
                c.N(e, "Type: " + DnsTypeLong(r.Type) + " (" + r.Type + ")", r.Start + nl, 2);
                c.N(e, "Class: " + cls + " (" + U.Hx(r.Class & 0x7FFF, 4) + ")", r.Start + nl + 2, 2);
                c.N(e, "Time to live: " + r.Ttl + " (" + TtlText(r.Ttl) + ")", r.Start + nl + 4, 4);
                c.N(e, "Data length: " + r.RdLen, r.Start + nl + 8, 2);
                if (r.Data != null && r.Data.Length > 0)
                {
                    string label = r.Type == 1 || r.Type == 28 ? "Address" : r.Type == 5 ? "CNAME" : r.Type == 2 ? "Name Server" : r.Type == 12 ? "Domain Name" : r.Type == 6 ? "Primary name server" : r.Type == 15 ? "Mail Exchange" : r.Type == 33 ? "Target" : "Text";
                    c.N(e, label + ": " + r.Data, r.RdStart, r.RdLen);
                }
            }
        }

        static string TtlText(uint s)
        {
            if (s < 60) return U.Plural(s, "second");
            if (s < 3600) return U.Plural(s / 60, "minute") + (s % 60 > 0 ? ", " + U.Plural(s % 60, "second") : "");
            if (s < 86400) return U.Plural(s / 3600, "hour") + (s % 3600 >= 60 ? ", " + U.Plural((s % 3600) / 60, "minute") : "");
            return U.Plural(s / 86400, "day") + (s % 86400 >= 3600 ? ", " + U.Plural((s % 86400) / 3600, "hour") : "");
        }

        // ---------------------------------------------------------------- DHCP
        static bool Dhcp(Ctx c, int off, int end)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            if (end - off < 240 || d[off + 236] != 0x63 || d[off + 237] != 0x82 || d[off + 238] != 0x53 || d[off + 239] != 0x63) return false;
            int op = d[off], htype = d[off + 1], hlen = d[off + 2], hops = d[off + 3];
            uint xid = U.L(d, off + 4);
            int secs = U.W(d, off + 8), bflags = U.W(d, off + 10);
            string msgType = null;
            int o = off + 240;
            List<int[]> opts = new List<int[]>();
            while (o < end)
            {
                int code = d[o];
                if (code == 0) { o++; continue; }
                if (code == 255) { opts.Add(new int[] { 255, 0, o }); break; }
                int l = d[o + 1];
                opts.Add(new int[] { code, l, o });
                if (code == 53) { string[] n = { "", "Discover", "Offer", "Request", "Decline", "ACK", "NAK", "Release", "Inform" }; int v = d[o + 2]; msgType = v < n.Length ? n[v] : "Type " + v; }
                o += 2 + l;
            }
            c.Chain.Add("dhcp");
            p.Protocol = "DHCP";
            p.Info = "DHCP " + (msgType ?? "Unknown").PadRight(9) + "- Transaction ID 0x" + xid.ToString("x");
            if (!c.T)
            {
                foreach (int[] oi in opts)
                {
                    int oc = oi[0], ol = oi[1], oo = oi[2];
                    if (oc == 53 && ol >= 1) p.AddApp("dhcp.option.dhcp", (long)d[oo + 2]);
                    else if (oc == 50 && ol >= 4) p.AddApp("dhcp.option.requested_ip_address", (long)U.L(d, oo + 2));
                    else if (oc == 54 && ol >= 4) p.AddApp("dhcp.option.dhcp_server_id", (long)U.L(d, oo + 2));
                    else if (oc == 12 && ol >= 1) p.AddApp("dhcp.option.hostname", U.Ascii(d, oo + 2, ol));
                }
                p.AddApp("dhcp.type", (long)d[off]);
                p.AddApp("dhcp.id", (long)xid);
                long macv = 0; for (int mi = 0; mi < 6; mi++) macv = (macv << 8) | d[off + 28 + mi];
                p.AddApp("dhcp.hw.mac_addr", macv);
                p.AddApp("dhcp.ip.client", (long)U.L(d, off + 12)); p.AddApp("dhcp.ip.your", (long)U.L(d, off + 16));
                p.AddApp("dhcp.ip.server", (long)U.L(d, off + 20)); p.AddApp("dhcp.ip.relay", (long)U.L(d, off + 24));
            }
            if (c.T)
            {
                TreeNode t = c.N(c.Root, "Dynamic Host Configuration Protocol (" + (msgType ?? "Unknown") + ")", off, end - off);
                c.N(t, "Message type: " + (op == 1 ? "Boot Request (1)" : "Boot Reply (2)"), off, 1);
                c.N(t, "Hardware type: " + (htype == 1 ? "Ethernet" : "Type") + " (" + U.Hx(htype, 2) + ")", off + 1, 1);
                c.N(t, "Hardware address length: " + hlen, off + 2, 1);
                c.N(t, "Hops: " + hops, off + 3, 1);
                c.N(t, "Transaction ID: " + U.Hx(xid, 8), off + 4, 4);
                c.N(t, "Seconds elapsed: " + secs, off + 8, 2);
                c.N(t, "Bootp flags: " + U.Hx(bflags, 4) + " (" + ((bflags & 0x8000) != 0 ? "Broadcast" : "Unicast") + ")", off + 10, 2);
                c.N(t, "Client IP address: " + U.Ip4(d, off + 12), off + 12, 4);
                c.N(t, "Your (client) IP address: " + U.Ip4(d, off + 16), off + 16, 4);
                c.N(t, "Next server IP address: " + U.Ip4(d, off + 20), off + 20, 4);
                c.N(t, "Relay agent IP address: " + U.Ip4(d, off + 24), off + 24, 4);
                c.N(t, "Client MAC address: " + U.MacFull(d, off + 28), off + 28, 6);
                c.N(t, "Client hardware address padding: " + U.HexStr(d, off + 34, 10), off + 34, 10);
                c.N(t, "Server host name not given", off + 44, 64);
                c.N(t, "Boot file name not given", off + 108, 128);
                c.N(t, "Magic cookie: DHCP", off + 236, 4);
                foreach (int[] oi in opts)
                {
                    int code = oi[0], l = oi[1], oo = oi[2];
                    string nm = DhcpOpt(code);
                    string val = "";
                    if (code == 53) val = " (" + msgType + ")";
                    else if ((code == 50 || code == 54 || code == 1 || code == 3 || code == 6 || code == 28) && l >= 4) val = " (" + U.Ip4(d, oo + 2) + ")";
                    else if (code == 12 || code == 15) val = ": " + U.Ascii(d, oo + 2, l);
                    else if (code == 51 || code == 58 || code == 59) val = ": (" + U.L(d, oo + 2) + "s)";
                    TreeNode on = c.N(t, "Option: (" + code + ") " + nm + val, oo, code == 255 ? 1 : 2 + l);
                    if (code != 255) c.N(on, "Length: " + l, oo + 1, 1);
                    if (code == 61 && l >= 2) c.N(on, "Client MAC address: " + (l >= 7 ? U.MacFull(d, oo + 3) : ""), oo + 3, l - 1);
                    if (code == 55) c.N(on, "Parameter Request List Item: " + l + " items", oo + 2, l);
                }
            }
            return true;
        }

        static string DhcpOpt(int code)
        {
            switch (code)
            {
                case 1: return "Subnet Mask"; case 3: return "Router"; case 6: return "Domain Name Server"; case 12: return "Host Name";
                case 15: return "Domain Name"; case 28: return "Broadcast Address"; case 50: return "Requested IP Address";
                case 51: return "IP Address Lease Time"; case 53: return "DHCP Message Type"; case 54: return "DHCP Server Identifier";
                case 55: return "Parameter Request List"; case 58: return "Renewal Time Value"; case 59: return "Rebinding Time Value";
                case 60: return "Vendor class identifier"; case 61: return "Client identifier"; case 255: return "End";
                default: return "Unknown";
            }
        }

        // ----------------------------------------------------------------- NTP
        static bool Ntp(Ctx c, int off, int end)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            if (end - off < 48) return false;
            int b0 = d[off], li = b0 >> 6, vn = (b0 >> 3) & 7, mode = b0 & 7;
            if (vn < 1 || vn > 4 || mode < 1 || mode > 5) return false;
            string[] modes = { "reserved", "symmetric active", "symmetric passive", "client", "server", "broadcast" };
            c.Chain.Add("ntp");
            p.Protocol = "NTP";
            p.Info = "NTP Version " + vn + ", " + modes[mode];
            if (c.T)
            {
                TreeNode t = c.N(c.Root, "Network Time Protocol (NTP Version " + vn + ", " + modes[mode] + ")", off, end - off);
                TreeNode f = c.N(t, "Flags: " + U.Hx(b0, 2) + ", Leap Indicator: " + (li == 0 ? "no warning" : li == 3 ? "unknown (clock unsynchronized)" : "warning") + ", Mode: " + modes[mode] + ", Version number: NTP Version " + vn, off, 1);
                c.N(f, U.Bits(8, 0xC0, (uint)b0) + " = Leap Indicator: " + (li == 0 ? "no warning" : li == 3 ? "unknown (clock unsynchronized)" : "warning") + " (" + li + ")", off, 1);
                c.N(f, U.Bits(8, 0x38, (uint)b0) + " = Version number: NTP Version " + vn + " (" + vn + ")", off, 1);
                c.N(f, U.Bits(8, 0x07, (uint)b0) + " = Mode: " + modes[mode] + " (" + mode + ")", off, 1);
                c.N(t, "Peer Clock Stratum: " + d[off + 1], off + 1, 1);
                c.N(t, "Peer Polling Interval: " + d[off + 2], off + 2, 1);
                c.N(t, "Peer Clock Precision: " + (sbyte)d[off + 3], off + 3, 1);
            }
            return true;
        }

        // ---------------------------------------------------------------- SSDP
        static bool Ssdp(Ctx c, int off, int end)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            string s = Encoding.ASCII.GetString(d, off, Math.Min(end - off, 1024));
            if (!(s.StartsWith("M-SEARCH ") || s.StartsWith("NOTIFY ") || s.StartsWith("HTTP/1."))) return false;
            c.Chain.Add("ssdp");
            p.Protocol = "SSDP";
            string[] lines = s.Split(new string[] { "\r\n" }, StringSplitOptions.None);
            p.Info = lines[0];
            if (c.T)
            {
                TreeNode t = c.N(c.Root, "Simple Service Discovery Protocol", off, end - off);
                int o = off;
                foreach (string ln in lines)
                {
                    if (o >= end) break;
                    c.N(t, ln + "\\r\\n", o, Math.Min(ln.Length + 2, end - o));
                    o += ln.Length + 2;
                }
            }
            return true;
        }

        // ---------------------------------------------------------------- HTTP
        static bool LooksHttp(byte[] d, int o, int end)
        {
            if (end - o < 5) return false;
            string[] m = { "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ", "HTTP/1." };
            foreach (string s in m)
            {
                if (end - o < s.Length) continue;
                bool ok = true;
                for (int i = 0; i < s.Length; i++) if (d[o + i] != (byte)s[i]) { ok = false; break; }
                if (ok) return true;
            }
            return false;
        }

        static void Http(Ctx c, int off, int end)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            c.Chain.Add("http");
            p.Protocol = "HTTP";
            string s = Encoding.ASCII.GetString(d, off, Math.Min(end - off, 8192));
            int hdrEnd = s.IndexOf("\r\n\r\n");
            string head = hdrEnd >= 0 ? s.Substring(0, hdrEnd) : s;
            string[] lines = head.Split(new string[] { "\r\n" }, StringSplitOptions.None);
            string first = lines[0];
            bool isResp = first.StartsWith("HTTP/1.");
            string ctype = null;
            for (int i = 1; i < lines.Length; i++)
                if (lines[i].StartsWith("Content-Type:", StringComparison.OrdinalIgnoreCase)) ctype = lines[i].Substring(13).Trim().Split(';')[0];
            p.Info = first + " " + (isResp && ctype != null ? " (" + ctype + ")" : "");
            if (!c.T)
            {
                p.AddApp(isResp ? "http.response" : "http.request", 1L);
                string[] rp = first.Split(new char[] { ' ' }, 3);
                if (isResp)
                {
                    p.AddApp("http.response.version", rp[0]);
                    long sc;
                    if (rp.Length > 1 && long.TryParse(rp[1], out sc)) p.AddApp("http.response.code", sc);
                    if (rp.Length > 2) p.AddApp("http.response.phrase", rp[2]);
                }
                else if (rp.Length >= 3) { p.AddApp("http.request.method", rp[0]); p.AddApp("http.request.uri", rp[1]); p.AddApp("http.request.version", rp[2]); }
                for (int hi = 1; hi < lines.Length; hi++)
                {
                    int ci = lines[hi].IndexOf(':');
                    if (ci <= 0) continue;
                    string hn = lines[hi].Substring(0, ci).Trim().ToLowerInvariant(), hv = lines[hi].Substring(ci + 1).Trim();
                    if (hn == "host") p.AddApp("http.host", hv);
                    else if (hn == "user-agent") p.AddApp("http.user_agent", hv);
                    else if (hn == "content-type") p.AddApp("http.content_type", hv);
                    else if (hn == "content-length") { long cl; if (long.TryParse(hv, out cl)) p.AddApp("http.content_length", cl); }
                }
                return;
            }
            TreeNode t = c.N(c.Root, "Hypertext Transfer Protocol", off, end - off);
            int o = off;
            for (int i = 0; i < lines.Length; i++)
            {
                string ln = lines[i];
                TreeNode ln0 = c.N(t, ln + "\\r\\n", o, ln.Length + 2);
                if (i == 0)
                {
                    string[] parts = ln.Split(new char[] { ' ' }, 3);
                    if (isResp && parts.Length >= 2)
                    {
                        c.N(ln0, "Response Version: " + parts[0], o, parts[0].Length);
                        c.N(ln0, "Status Code: " + parts[1], o + parts[0].Length + 1, parts[1].Length);
                        if (parts.Length > 2) { c.N(ln0, "[Status Code Description: " + parts[2] + "]", o, ln.Length); c.N(ln0, "Response Phrase: " + parts[2], o + parts[0].Length + parts[1].Length + 2, parts[2].Length); }
                    }
                    else if (parts.Length >= 3)
                    {
                        c.N(ln0, "Request Method: " + parts[0], o, parts[0].Length);
                        c.N(ln0, "Request URI: " + parts[1], o + parts[0].Length + 1, parts[1].Length);
                        c.N(ln0, "Request Version: " + parts[2], o + parts[0].Length + parts[1].Length + 2, parts[2].Length);
                    }
                }
                o += ln.Length + 2;
            }
            if (hdrEnd >= 0)
            {
                c.N(t, "\\r\\n", o, 2);
                o += 2;
                if (o < end) c.N(t, "File Data: " + (end - o) + " bytes", o, end - o);
            }
        }

        // ----------------------------------------------------------------- TLS
        static bool LooksTls(byte[] d, int o, int end, bool enc)
        {
            if (end - o < 5) return false;
            int ct = d[o], ver = U.W(d, o + 1), rl = U.W(d, o + 3);
            if (ct < 20 || ct > 23 || ver < 0x0300 || ver > 0x0304 || rl > 16384 + 2048) return false;
            if (ct == 22 && !enc && end - o >= 6)
            {
                int ht = d[o + 5];
                if (!(ht == 0 || ht == 1 || ht == 2 || ht == 4 || ht == 5 || ht == 8 || (ht >= 11 && ht <= 16) || ht == 20 || ht == 24)) return false;
            }
            return true;
        }

        static string TlsVerName(int v)
        {
            switch (v) { case 0x0300: return "SSLv3"; case 0x0301: return "TLSv1"; case 0x0302: return "TLSv1.1"; case 0x0303: return "TLSv1.2"; case 0x0304: return "TLSv1.3"; default: return "TLS"; }
        }
        static string TlsVerText(int v)
        {
            switch (v) { case 0x0300: return "SSL 3.0"; case 0x0301: return "TLS 1.0"; case 0x0302: return "TLS 1.1"; case 0x0303: return "TLS 1.2"; case 0x0304: return "TLS 1.3"; default: return "Unknown"; }
        }
        static string HsName(int t)
        {
            switch (t)
            {
                case 0: return "Hello Request"; case 1: return "Client Hello"; case 2: return "Server Hello"; case 4: return "New Session Ticket";
                case 5: return "End of Early Data"; case 8: return "Encrypted Extensions"; case 11: return "Certificate"; case 12: return "Server Key Exchange";
                case 13: return "Certificate Request"; case 14: return "Server Hello Done"; case 15: return "Certificate Verify";
                case 16: return "Client Key Exchange"; case 20: return "Finished"; case 24: return "Key Update"; default: return "Handshake (" + t + ")";
            }
        }
        static string AlertDesc(int a)
        {
            switch (a) { case 0: return "Close Notify"; case 10: return "Unexpected Message"; case 20: return "Bad Record MAC"; case 40: return "Handshake Failure"; case 42: return "Bad Certificate"; case 46: return "Certificate Unknown"; case 48: return "Unknown CA"; case 70: return "Protocol Version"; case 80: return "Internal Error"; case 90: return "User Canceled"; default: return "Description " + a; }
        }

        // Walks the TLS records in one segment. Stream state (s) is only present in the stateful pass.
        static void Tls(Ctx c, int off, int end, TcpStream s, int dir)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            c.Chain.Add("tls");
            bool tls13 = c.T ? p.Tls13Start : (s != null && s.Tls13);
            bool enc = c.T ? p.TlsEncStart : (s != null && s.Enc[dir]);
            if (!c.T) { p.Tls13Start = tls13; p.TlsEncStart = enc; }
            TreeNode t = c.N(c.Root, "Transport Layer Security", off, end - off);
            List<string> infos = new List<string>();
            string proto = null;
            int o = off;
            if (!LooksTls(d, o, end, enc))
            {
                proto = p.TlsProto ?? "TLSv1.2";
                if (s != null && s.Tls) proto = tls13 ? "TLSv1.3" : proto;
                infos.Add("Continuation Data");
                if (c.T) c.N(t, proto + " Record Layer: Continuation Data", o, end - o);
                o = end;
            }
            while (end - o >= 5)
            {
                int ct = d[o], rv = U.W(d, o + 1), rl = U.W(d, o + 3);
                if (ct < 20 || ct > 23) break;
                int bodyEnd = Math.Min(o + 5 + rl, end);
                proto = tls13 ? "TLSv1.3" : TlsVerName(rv);
                string ri;
                string ctName = ct == 20 ? "Change Cipher Spec" : ct == 21 ? "Alert" : ct == 22 ? "Handshake" : "Application Data";
                List<string> hs = new List<string>();
                List<int[]> hsPos = new List<int[]>();
                string sni = null;
                bool offered13 = false;
                if (ct == 20) { ri = "Change Cipher Spec"; if (!tls13) enc = true; }
                else if (ct == 21)
                {
                    if (enc) ri = "Encrypted Alert";
                    else ri = "Alert (Level: " + (d[o + 5] == 2 ? "Fatal" : "Warning") + ", Description: " + AlertDesc(d[o + 6]) + ")";
                }
                else if (ct == 22)
                {
                    if (enc) { ri = "Encrypted Handshake Message"; }
                    else
                    {
                        int h = o + 5;
                        while (h + 4 <= bodyEnd)
                        {
                            int ht = d[h];
                            int hl = (d[h + 1] << 16) | (d[h + 2] << 8) | d[h + 3];
                            string nm = HsName(ht);
                            bool whole = h + 4 + hl <= bodyEnd;
                            if (ht == 1 && whole)
                            {
                                string host = null; bool v13 = false;
                                ParseHello(d, h + 4, h + 4 + hl, true, out host, out v13);
                                if (host != null) { nm += " (SNI=" + host + ")"; sni = host; }
                                if (v13) offered13 = true;
                            }
                            else if (ht == 2 && whole)
                            {
                                string host; bool v13 = false;
                                ParseHello(d, h + 4, h + 4 + hl, false, out host, out v13);
                                if (v13) { tls13 = true; proto = "TLSv1.3"; }
                            }
                            hs.Add(nm); hsPos.Add(new int[] { h, hl + 4, ht });
                            h += 4 + hl;
                        }
                        ri = hs.Count > 1 ? null : (hs.Count == 1 ? hs[0] : "Handshake Message");
                        if (ri == null) ri = string.Join(", ", hs.ToArray());
                    }
                }
                else ri = "Application Data";
                infos.Add(ri);
                if (!c.T)
                {
                    p.AddApp(tls13 && ct == 23 ? "tls.record.opaque_type" : "tls.record.content_type", (long)ct); p.AddApp("tls.record.version", (long)rv);
                    foreach (int[] hp in hsPos) p.AddApp("tls.handshake.type", (long)hp[2]);
                    if (sni != null) p.AddApp("tls.handshake.extensions_server_name", sni);
                }
                if (c.T)
                {
                    string rt = ct == 21 ? ri : ct == 22 ? (enc ? "Handshake Protocol: Encrypted Handshake Message" : "Handshake Protocol: " + (hs.Count > 1 ? "Multiple Handshake Messages" : (hs.Count == 1 ? hs[0] : "Handshake Message")))
                                            : ct == 20 ? "Change Cipher Spec Protocol: Change Cipher Spec" : "Application Data Protocol: Application Data";
                    TreeNode rec = c.N(t, proto + " Record Layer: " + rt, o, bodyEnd - o);
                    c.N(rec, "Content Type: " + ctName + " (" + ct + ")", o, 1);
                    c.N(rec, "Version: " + TlsVerText(rv) + " (" + U.Hx(rv, 4) + ")", o + 1, 2);
                    c.N(rec, "Length: " + rl, o + 3, 2);
                    if (ct == 23) c.N(rec, "Encrypted Application Data: " + U.HexStr(d, o + 5, Math.Min(bodyEnd - o - 5, 48)) + (bodyEnd - o - 5 > 48 ? "..." : ""), o + 5, bodyEnd - o - 5);
                    else if (ct == 20) c.N(rec, "Change Cipher Spec Message", o + 5, bodyEnd - o - 5);
                    else if (ct == 21 && !enc) { c.N(rec, "Alert Message", o + 5, 2); }
                    else if (ct == 22 && enc) c.N(rec, "Handshake Protocol: Encrypted Handshake Message", o + 5, bodyEnd - o - 5);
                    else if (ct == 22)
                        foreach (int[] hp in hsPos)
                        {
                            TreeNode hn = c.N(rec, "Handshake Protocol: " + HsName(hp[2]), hp[0], Math.Min(hp[1], bodyEnd - hp[0]));
                            c.N(hn, "Handshake Type: " + HsName(hp[2]) + " (" + hp[2] + ")", hp[0], 1);
                            c.N(hn, "Length: " + (hp[1] - 4), hp[0] + 1, 3);
                            if ((hp[2] == 1 || hp[2] == 2) && hp[0] + 6 <= bodyEnd) c.N(hn, "Version: " + TlsVerText(U.W(d, hp[0] + 4)) + " (" + U.Hx(U.W(d, hp[0] + 4), 4) + ")", hp[0] + 4, 2);
                            if (hp[2] == 1 && sni != null) c.N(hn, "Extension: server_name (len=" + (sni.Length + 5) + ") name=" + sni, hp[0], 0);
                        }
                }
                if (offered13) tls13 = true;
                o = o + 5 + rl;
            }
            p.Protocol = proto ?? "TLSv1.2";
            p.TlsProto = p.Protocol;
            p.Info = string.Join(", ", infos.ToArray());
            if (s != null) { s.Tls = true; s.Tls13 = tls13; s.Enc[dir] = enc; s.TlsLabel = p.Protocol; }
        }

        // Extracts SNI and supported_versions (TLS 1.3) from a Hello body [o, e).
        static void ParseHello(byte[] d, int o, int e, bool client, out string sni, out bool v13)
        {
            sni = null; v13 = false;
            try
            {
                o += 2 + 32;
                o += 1 + d[o];
                if (client) { o += 2 + U.W(d, o); o += 1 + d[o]; }
                else { o += 3; }
                if (o + 2 > e) return;
                int extEnd = Math.Min(o + 2 + U.W(d, o), e);
                o += 2;
                while (o + 4 <= extEnd)
                {
                    int et = U.W(d, o), el = U.W(d, o + 2);
                    int ds = o + 4;
                    if (et == 0 && client && ds + 5 <= extEnd) sni = Encoding.ASCII.GetString(d, ds + 5, Math.Min(U.W(d, ds + 3), extEnd - ds - 5));
                    else if (et == 43)
                    {
                        if (client) { int n = d[ds]; for (int i = 0; i + 1 < n && ds + 2 + i < extEnd; i += 2) if (U.W(d, ds + 1 + i) == 0x0304) v13 = true; }
                        else if (el >= 2 && U.W(d, ds) == 0x0304) v13 = true;
                    }
                    o = ds + el;
                }
            }
            catch (IndexOutOfRangeException) { }
            catch (ArgumentException) { }
        }
    }
}

namespace PSShark
{
    // ------------------------------------------------------------------ TCP reassembly
    // One pending (incomplete) protocol data unit per stream direction. Segments are appended until the
    // PDU (an HTTP message, a TLS record or a DNS-over-TCP message) is complete; the completing segment is
    // then dissected from the assembled bytes, the way Wireshark shows it.
    internal class OooSeg { public byte[] Data; public Packet Pkt; }

    internal class Reasm
    {
        public bool Active;
        public int Kind;                       // 1 = HTTP, 2 = TLS, 3 = DNS over TCP
        public uint Next;                      // next expected sequence number
        public byte[] Buf = new byte[0];
        public int Len;
        public List<Packet> Pkts = new List<Packet>();
        public List<int> Lens = new List<int>();
        public SortedDictionary<uint, OooSeg> Ooo;

        public void Reset()
        {
            Active = false; Len = 0; Pkts.Clear(); Lens.Clear(); Ooo = null;
        }
        public void Add(byte[] src, int off, int n, Packet pk)
        {
            if (Len + n > Buf.Length) Array.Resize(ref Buf, Math.Max(Buf.Length * 2, Len + n));
            Array.Copy(src, off, Buf, Len, n);
            Len += n; Next += (uint)n;
            Pkts.Add(pk); Lens.Add(n);
        }
    }

    public partial class Dissector
    {
        const int MaxPdu = 4 * 1024 * 1024;

        // ---- how long is the PDU that starts at d[o]?   1 = complete (total set), 0 = need more bytes,
        //      -1 = not a PDU of this kind, 2 = HTTP response with no usable length (headers only)
        static int NeedLen(int kind, byte[] d, int o, int end, out int total)
        {
            total = 0;
            int avail = end - o;
            if (kind == 2)
            {
                if (avail >= 1 && (d[o] < 20 || d[o] > 23)) return -1;
                if (avail >= 3 && (d[o + 1] != 3 || d[o + 2] > 4)) return -1;
                if (avail < 5) return 0;
                int rl = U.W(d, o + 3);
                if (rl > 16384 + 2048) return -1;
                total = 5 + rl;
                return avail >= total ? 1 : 0;
            }
            if (kind == 3)
            {
                if (avail < 2) return 0;
                total = 2 + U.W(d, o);
                if (total < 14) return -1;
                return avail >= total ? 1 : 0;
            }
            // HTTP
            int hend = -1;
            int limit = Math.Min(end - 3, o + 65536);
            for (int i = o; i < limit; i++)
                if (d[i] == 13 && d[i + 1] == 10 && d[i + 2] == 13 && d[i + 3] == 10) { hend = i; break; }
            if (hend < 0) return (avail > 65536) ? -1 : 0;
            int hdrLen = hend + 4 - o;
            string head = Encoding.ASCII.GetString(d, o, hend - o);
            string[] lines = head.Split(new string[] { "\r\n" }, StringSplitOptions.None);
            bool isResp = lines[0].StartsWith("HTTP/");
            long cl = -1; bool chunked = false;
            for (int i = 1; i < lines.Length; i++)
            {
                int ci = lines[i].IndexOf(':');
                if (ci <= 0) continue;
                string hn = lines[i].Substring(0, ci).Trim().ToLowerInvariant(), hv = lines[i].Substring(ci + 1).Trim();
                if (hn == "content-length") { long v; if (long.TryParse(hv, out v)) cl = v; }
                else if (hn == "transfer-encoding" && hv.ToLowerInvariant().IndexOf("chunked") >= 0) chunked = true;
            }
            if (isResp)
            {
                string[] parts = lines[0].Split(' ');
                int code; if (parts.Length > 1 && int.TryParse(parts[1], out code) && ((code >= 100 && code < 200) || code == 204 || code == 304)) { total = hdrLen; return 1; }
            }
            if (chunked)
            {
                int pos = o + hdrLen;
                while (true)
                {
                    int le = -1;
                    for (int i = pos; i + 1 < end && i < pos + 40; i++) if (d[i] == 13 && d[i + 1] == 10) { le = i; break; }
                    if (le < 0) return (end - pos > 40) ? -1 : 0;
                    string sz = Encoding.ASCII.GetString(d, pos, le - pos).Split(';')[0].Trim();
                    long n;
                    if (!long.TryParse(sz, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out n) || n < 0 || n > MaxPdu) return -1;
                    pos = le + 2;
                    if (n == 0)
                    {
                        // optional trailer lines, then an empty line
                        while (true)
                        {
                            int te = -1;
                            for (int i = pos; i + 1 < end; i++) if (d[i] == 13 && d[i + 1] == 10) { te = i; break; }
                            if (te < 0) return 0;
                            if (te == pos) { total = te + 2 - o; return 1; }
                            pos = te + 2;
                        }
                    }
                    pos += (int)n + 2;
                    if (pos > end) return 0;
                    if (pos - o > MaxPdu) return 2;
                }
            }
            if (cl >= 0)
            {
                if (cl > MaxPdu) return 2;
                total = hdrLen + (int)cl;
                return avail >= total ? 1 : 0;
            }
            if (isResp) return 2;             // body runs until the connection closes
            total = hdrLen;                   // request without a body
            return 1;
        }

        static int Detect(byte[] d, int o, int end, int sport, int dport, bool tlsSeen, bool enc)
        {
            if (LooksHttp(d, o, end)) return 1;
            int avail = end - o;
            if (LooksTls(d, o, end, enc)) return 2;
            if (avail >= 1 && avail < 5 && d[o] >= 20 && d[o] <= 23 &&
                ((avail >= 3 && d[o + 1] == 3 && d[o + 2] <= 4) || (tlsSeen && (avail < 2 || d[o + 1] == 3)))) return 2;
            if ((sport == 443 || dport == 443) && avail >= 1 && d[o] >= 20 && d[o] <= 23 && (avail < 2 || d[o + 1] == 3)) return 2;
            if ((sport == 53 || dport == 53) && avail >= 2) return 3;
            return 0;
        }

        // Returns 0 = dissect this segment on its own, 1 = a reassembled PDU was dissected here,
        //         2 = plain TCP row (part of a PDU that is still incomplete), 3 = dissect on its own up to p.DEnd
        static int Reassemble(Ctx c, TcpStream s, int dir, uint seq, int poff, int end)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            int len = end - poff;
            Reasm R = s.R[dir];
            if (R == null) { R = new Reasm(); s.R[dir] = R; }

            if (R.Active)
            {
                int diff = (int)(seq - R.Next);
                int skip = 0;
                if (diff > 0)
                {
                    // a later segment arrived first: keep it until the gap is filled
                    if (R.Ooo == null) R.Ooo = new SortedDictionary<uint, OooSeg>();
                    if (R.Ooo.Count < 64 && !R.Ooo.ContainsKey(seq))
                    {
                        OooSeg o = new OooSeg(); o.Data = new byte[len]; Array.Copy(d, poff, o.Data, 0, len); o.Pkt = p;
                        R.Ooo[seq] = o;
                    }
                    p.SegOfPdu = true;
                    return 2;
                }
                if (diff < 0)
                {
                    skip = -diff;
                    if (skip >= len) { p.SegOfPdu = true; return 2; }    // pure duplicate
                }
                int own = len - skip;
                int ownStart = R.Len;
                R.Add(d, poff + skip, own, p);
                while (R.Ooo != null && R.Ooo.Count > 0)
                {
                    OooSeg o;
                    if (!R.Ooo.TryGetValue(R.Next, out o)) break;
                    R.Ooo.Remove(R.Next);
                    R.Add(o.Data, 0, o.Data.Length, o.Pkt);
                }
                if (R.Len > MaxPdu) { R.Reset(); return 0; }
                return Complete(c, s, dir, R, poff + skip, own, ownStart);
            }

            if (p.TcpNote == "TCP Retransmission" && s.Delivered[dir] != null)
            {
                foreach (uint[] dv in s.Delivered[dir])
                    if ((int)(seq - dv[0]) >= 0 && (int)(dv[1] - seq) > 0) { p.ReasmIn = (int)dv[2]; p.Info += " [TCP PDU reassembled in " + dv[2] + "]"; break; }
            }
            if (p.TcpNote != null) return 0;
            int kind = Detect(d, poff, end, p.SrcPort, p.DstPort, s.Tls, s.Enc[dir]);
            if (kind == 0) return 0;
            int off = poff, partial = -1;
            bool noLen = false;
            while (off < end)
            {
                int total;
                int st = NeedLen(kind, d, off, end, out total);
                if (st == 1) { off += total; continue; }
                if (st == 0) partial = off;
                else if (st == 2) noLen = true;
                break;
            }
            if (partial < 0)
            {
                if (noLen && off == poff) { p.SegOfPdu = true; FirstSegment(c, s, 1, poff, end); return 2; }
                return 0;                       // every PDU in the segment is complete: normal dissection
            }
            // a PDU starts at `partial` and continues in later segments
            R.Reset();
            R.Active = true; R.Kind = kind; R.Next = seq + (uint)(partial - poff);
            R.Add(d, partial, end - partial, p);
            p.SegOfPdu = true;
            if (partial > poff) { p.DEnd = partial; return 3; }
            FirstSegment(c, s, kind, poff, end);
            return 2;
        }

        // How Wireshark labels the first segment of a PDU that is not complete yet.
        static void FirstSegment(Ctx c, TcpStream s, int kind, int poff, int end)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            if (kind == 1)
            {
                int e = -1;
                for (int i = poff; i + 1 < end; i++) if (d[i] == 13 && d[i + 1] == 10) { e = i; break; }
                if (e > poff) p.Info = Encoding.ASCII.GetString(d, poff, e - poff) + " ";
            }
            else if (kind == 2)
            {
                c.Chain.Add("tls");
                p.Protocol = s.TlsLabel ?? "SSL";
                p.Info = "";
            }
        }

        static int Complete(Ctx c, TcpStream s, int dir, Reasm R, int ownOff, int ownLen, int ownStart)
        {
            Packet p = c.P;
            int done = 0;
            while (done < R.Len)
            {
                int total;
                if (NeedLen(R.Kind, R.Buf, done, R.Len, out total) == 1) done += total; else break;
            }
            if (done == 0) { p.SegOfPdu = true; return 2; }

            int firstLen;
            NeedLen(R.Kind, R.Buf, 0, R.Len, out firstLen);
            p.ReasmData = new byte[done];
            Array.Copy(R.Buf, p.ReasmData, done);
            p.ReasmKind = R.Kind;
            p.ReasmPduLen = firstLen;
            List<int> nos = new List<int>(), lens = new List<int>();
            int pos = 0;
            for (int i = 0; i < R.Pkts.Count; i++)
            {
                int clipped = Math.Max(0, Math.Min(firstLen, pos + R.Lens[i]) - pos);
                if (clipped > 0)
                {
                    nos.Add(R.Pkts[i].No); lens.Add(clipped);
                    if (R.Pkts[i] != p) R.Pkts[i].ReasmIn = p.No;
                }
                pos += R.Lens[i];
            }
            p.ReasmNos = nos.ToArray(); p.ReasmLens = lens.ToArray();
            p.ReasmOwnOff = ownOff; p.ReasmOwnStart = ownStart; p.ReasmOwnLen = Math.Max(0, Math.Min(done, ownStart + ownLen) - ownStart);
            DissectAssembled(c, s, dir);
            if (p.TcpNote != null) p.Info = "[" + p.TcpNote + "] " + p.Info;

            // bytes after the last complete PDU may start the next one
            int left = R.Len - done;
            uint nextSeq = R.Next;
            if (s.Delivered[dir] == null) s.Delivered[dir] = new List<uint[]>();
            uint firstSeq = nextSeq - (uint)R.Len;
            s.Delivered[dir].Add(new uint[] { firstSeq, firstSeq + (uint)done, (uint)p.No });
            if (s.Delivered[dir].Count > 32) s.Delivered[dir].RemoveAt(0);
            if (left > 0)
            {
                byte[] rest = new byte[left];
                Array.Copy(R.Buf, done, rest, 0, left);
                int total;
                int kind = R.Kind;
                R.Reset();
                if (NeedLen(kind, rest, 0, left, out total) == 0)
                {
                    R.Active = true; R.Kind = kind; R.Next = nextSeq - (uint)left;
                    R.Add(rest, 0, left, p);
                }
            }
            else R.Reset();
            return 1;
        }

        // Dissects the assembled bytes (p.ReasmData). Used by the stateful pass and, without stream state, by the tree pass.
        static void DissectAssembled(Ctx c, TcpStream s, int dir)
        {
            Packet p = c.P;
            byte[] buf = p.ReasmData;
            int done = buf.Length;
            Packet q = new Packet();
            q.Data = buf; q.OrigLen = done; q.LinkType = p.LinkType; q.No = p.No;
            q.SrcPort = p.SrcPort; q.DstPort = p.DstPort; q.Chain = string.Join(":", c.Chain.ToArray());
            q.Tls13Start = p.Tls13Start; q.TlsEncStart = p.TlsEncStart; q.TlsProto = p.TlsProto;
            Ctx c2 = new Ctx();
            c2.P = q; c2.D = c.D; c2.T = c.T; c2.Chain = c.Chain;
            c2.Root = c.T ? new TreeNode("", 0, 0) : null;
            try
            {
                switch (p.ReasmKind)
                {
                    case 1: HttpMulti(c2, 0, done); break;
                    case 2: Tls(c2, 0, done, s, dir); break;
                    default: Dns(c2, 2, Math.Min(done, 2 + U.W(buf, 0)), "DNS"); break;
                }
            }
            catch (IndexOutOfRangeException) { }
            catch (ArgumentException) { }
            if (!c.T)
            {
                p.Protocol = q.Protocol; p.Info = q.Info;
                p.TlsProto = q.TlsProto; p.Tls13Start = q.Tls13Start; p.TlsEncStart = q.TlsEncStart;
                if (q.App != null) foreach (KeyValuePair<string, List<object>> kv in q.App) foreach (object v in kv.Value) p.AddApp(kv.Key, v);
            }
            else
            {
                foreach (TreeNode n in c2.Root.Children) { Remap(n, p.ReasmOwnStart, p.ReasmOwnLen, p.ReasmOwnOff); c.Root.Children.Add(n); }
            }
        }

        // Byte ranges in the assembled data map back onto this frame's own bytes; the rest cannot be highlighted.
        static void Remap(TreeNode n, int ownStart, int ownLen, int ownOff)
        {
            int lo = Math.Max(n.Start, ownStart), hi = Math.Min(n.Start + n.Length, ownStart + ownLen);
            if (n.Length > 0 && hi > lo) { n.Start = ownOff + (lo - ownStart); n.Length = hi - lo; }
            else { n.Start = 0; n.Length = 0; }
            foreach (TreeNode ch in n.Children) Remap(ch, ownStart, ownLen, ownOff);
        }

        // Every complete HTTP message in [off, end): the Info column lists them one after another.
        static void HttpMulti(Ctx c, int off, int end)
        {
            Packet p = c.P;
            byte[] d = p.Data;
            StringBuilder info = new StringBuilder();
            int o = off;
            while (o < end)
            {
                int total;
                int st = NeedLen(1, d, o, end, out total);
                int mend = (st == 1) ? o + total : end;
                Http(c, o, mend);
                info.Append(p.Info);
                if (st != 1) break;
                o = mend;
                if (o >= end || !LooksHttp(d, o, end)) break;
            }
            p.Info = info.ToString();
        }
    }
}
// ==== PKTMON-TEXT-BEGIN

namespace PSShark
{
    // ------------------------------------------------------------------ text export (pktmon etl2txt style)
    // Each packet becomes a header line (timestamp, PktGroupId, PktNumber, ...) followed by the packet decoded in
    // tcpdump style, like the text that "pktmon etl2txt" produces from a Packet Monitor ETL log.
    public static class PktmonText
    {
        static string MacDash(byte[] d, int o)
        {
            return d[o].ToString("X2") + "-" + d[o + 1].ToString("X2") + "-" + d[o + 2].ToString("X2") + "-" +
                   d[o + 3].ToString("X2") + "-" + d[o + 4].ToString("X2") + "-" + d[o + 5].ToString("X2");
        }
        static string Hex4(int v) { return "0x" + v.ToString("x4"); }

        // "[ 0]0000.0000::2023-01-12 11:33:51.839176100 [Microsoft-Windows-PktMon] PktGroupId ..., LoggedSize 66"
        public static string Header(Packet p, int number)
        {
            DateTime t = new DateTime(p.Ticks, DateTimeKind.Utc).ToLocalTime();
            string type = p.LinkType == 105 ? "Wi-Fi" : (p.LinkType == 1 || p.LinkType == 113 || p.LinkType == 0) ? "Ethernet" : "IP";
            string dir = p.Dir == 1 ? "Tx" : "Rx";
            return "[ 0]0000.0000::" + t.ToString("yyyy-MM-dd HH:mm:ss.fffffff", CultureInfo.InvariantCulture) + "00 [Microsoft-Windows-PktMon] PktGroupId " +
                   (281474976710656L + number) + ", PktNumber " + number + ", Appearance 1, Direction " + dir + " , Type " + type + " , Component 1, Edge 1, Filter 1, OriginalSize " +
                   p.OrigLen + ", LoggedSize " + p.Data.Length;
        }

        // Decoded lines (no trailing newline); the caller indents them.
        public static List<string> Decode(Packet p)
        {
            List<string> lines = new List<string>();
            byte[] d = p.Data;
            try
            {
                if (p.LinkType == 1) Ethernet(d, p.OrigLen, lines);
                else if (p.LinkType == 101 || p.LinkType == 228 || p.LinkType == 229 || p.LinkType == 12 || p.LinkType == 14) Network(d, 0, d[0] >> 4 == 6 ? 0x86DD : 0x0800, "", lines);
                else HexLines(d, 0, d.Length, lines);
            }
            catch (IndexOutOfRangeException) { lines.Add("[|truncated]"); }
            catch (ArgumentException) { lines.Add("[|truncated]"); }
            if (lines.Count == 0) lines.Add("");
            return lines;
        }

        // ---------------------------------------------------------------- layer 2
        static string EtherName(int t)
        {
            switch (t)
            {
                case 0x0800: return "IPv4 (0x0800)"; case 0x86DD: return "IPv6 (0x86dd)"; case 0x0806: return "ARP (0x0806)";
                case 0x8100: return "802.1Q (0x8100)"; case 0x88CC: return "LLDP (0x88cc)"; case 0x888E: return "EAPOL (0x888e)";
                case 0x8847: return "MPLS unicast (0x8847)"; case 0x88A8: return "802.1ad (0x88a8)";
                default: return "Unknown (" + Hex4(t) + ")";
            }
        }

        static void Ethernet(byte[] d, int origLen, List<string> lines)
        {
            string head = MacDash(d, 6) + " > " + MacDash(d, 0);
            int et = U.W(d, 12), off = 14;
            if (et <= 1500)
            {
                string llc = Llc(d, 14, et);
                lines.Add(head + ", 802.3, length " + et + ": " + llc);
                return;
            }
            head += ", ethertype " + EtherName(et) + ", length " + origLen + ": ";
            if (et == 0x88CC) { lines.Add(head + "LLDP, length " + Math.Max(0, d.Length - 14)); return; }
            string vl = "";
            while (et == 0x8100 || et == 0x88A8)
            {
                int tci = U.W(d, off);
                et = U.W(d, off + 2); off += 4;
                vl += "vlan " + (tci & 0xFFF) + ", p " + (tci >> 13) + ", ethertype " + EtherName(et).Split(' ')[0].Replace("Unknown", "Unknown (" + Hex4(et) + ")") + ", ";
            }
            Network(d, off, et, head + vl, lines);
        }

        static string Llc(byte[] d, int o, int len)
        {
            int dsap = d[o], ssap = d[o + 1], ctl = d[o + 2];
            string dn = dsap == 0x42 ? "STP (0x42)" : dsap == 0 ? "Null (0x00)" : dsap == 0xAA ? "SNAP (0xaa)" : U.Hx(dsap, 2);
            int ss = ssap & 0xFE;
            string sn = ss == 0x42 ? "STP (0x42)" : ss == 0 ? "Null (0x00)" : ss == 0xAA ? "SNAP (0xaa)" : U.Hx(ss, 2);
            string s = "LLC, dsap " + dn + " " + ((dsap & 1) != 0 ? "Group" : "Individual") + ", ssap " + sn + " " + ((ssap & 1) != 0 ? "Response" : "Command") + ", ctrl " + U.Hx(ctl, 2);
            if (dsap == 0x42 && ssap == 0x42 && ctl == 3) return s + ": " + Stp(d, o + 3, len - 3);
            if ((ctl & 3) == 3)
            {
                bool xid = (ctl & 0xEF) == 0xAF;
                StringBuilder sb = new StringBuilder(s + ": Unnumbered, " + (xid ? "xid" : (ctl & 0xEF) == 0x03 ? "ui" : "u") + ", Flags [" + ((ssap & 1) != 0 ? "Response" : "Command") + "], length " + len);
                int skip = xid ? 1 : 0;
                if (len > 3 + skip) { sb.Append(": "); for (int i = 0; i < len - 3 - skip && o + 3 + skip + i < d.Length; i++) { if (i > 0) sb.Append(' '); sb.Append(d[o + 3 + skip + i].ToString("x2")); } }
                return sb.ToString();
            }
            return s + ", length " + len;
        }

        static string BridgeId(byte[] d, int o)
        {
            return U.W(d, o).ToString("x4") + "." + U.Mac(d, o + 2) + "";
        }

        static string Stp(byte[] d, int o, int len)
        {
            int ver = d[o + 2], type = d[o + 3];
            string vs = ver == 0 ? "802.1d" : ver == 2 ? "802.1w" : ver == 3 ? "802.1s" : "ver " + ver;
            if (type == 0x80) return "STP " + vs + ", Topology Change Notification";
            int flags = d[o + 4];
            string root = BridgeId(d, o + 5);
            uint cost = U.L(d, o + 13);
            string bridge = BridgeId(d, o + 17) + "." + U.W(d, o + 25).ToString("x4");
            string tn = type == 2 ? "RSTP" : "Config";
            List<string> sf = new List<string>();
            if ((flags & 1) != 0) sf.Add("Topology Change"); if ((flags & 0x80) != 0) sf.Add("Topology Change ACK");
            return "STP " + vs + ", " + tn + ", Flags [" + (sf.Count == 0 ? "none" : string.Join(", ", sf.ToArray())) + "], bridge-id " + bridge +
                   ", length " + len + "\n\tmessage-age " + Sec(U.W(d, o + 27)) + ", max-age " + Sec(U.W(d, o + 29)) + ", hello-time " + Sec(U.W(d, o + 31)) + ", forwarding-delay " + Sec(U.W(d, o + 33)) +
                   "\n\troot-id " + root + ", root-pathcost " + cost;
        }
        static string Sec(int v256) { return (v256 / 256.0).ToString("0.00", CultureInfo.InvariantCulture) + "s"; }

        // ---------------------------------------------------------------- layer 3
        static void Network(byte[] d, int off, int et, string head, List<string> lines)
        {
            if (et == 0x0800) { Ipv4(d, off, head, lines); return; }
            if (et == 0x86DD) { Ipv6(d, off, head, lines); return; }
            if (et == 0x0806) { lines.Add(head + Arp(d, off)); return; }
            lines.Add(head.TrimEnd());
            HexLines(d, off, d.Length, lines);
        }

        static string Arp(byte[] d, int o)
        {
            int op = U.W(d, o + 6);
            string sip = U.Ip4(d, o + 14), tip = U.Ip4(d, o + 24);
            string s = "Ethernet (len " + d[o + 4] + "), IPv4 (len " + d[o + 5] + "), ";
            if (op == 1) s += "Request who-has " + tip + " tell " + sip;
            else if (op == 2) s += "Reply " + sip + " is-at " + MacDash(d, o + 8);
            else s += "unknown-op-" + op;
            return s + ", length 28";
        }

        static string ProtoName(int p)
        {
            switch (p)
            {
                case 1: return "ICMP (1)"; case 2: return "IGMP (2)"; case 6: return "TCP (6)"; case 17: return "UDP (17)"; case 47: return "GRE (47)";
                case 50: return "ESP (50)"; case 51: return "AH (51)"; case 58: return "ICMPv6 (58)"; case 89: return "OSPF (89)"; case 132: return "SCTP (132)";
                default: return "unknown (" + p + ")";
            }
        }

        static void Ipv4(byte[] d, int o, string head, List<string> lines)
        {
            int ihl = (d[o] & 0xF) * 4, tos = d[o + 1], total = U.W(d, o + 2), id = U.W(d, o + 4), ff = U.W(d, o + 6), ttl = d[o + 8], proto = d[o + 9];
            string src = U.Ip4(d, o + 12), dst = U.Ip4(d, o + 16);
            List<string> fls = new List<string>(); if ((ff & 0x2000) != 0) fls.Add("+"); if ((ff & 0x4000) != 0) fls.Add("DF");
            string fl = fls.Count == 0 ? "none" : string.Join(", ", fls.ToArray());
            string ecn = (tos & 3) == 1 ? ",ECT(1)" : (tos & 3) == 2 ? ",ECT(0)" : (tos & 3) == 3 ? ",CE" : "";
            StringBuilder h = new StringBuilder();
            h.Append("(tos 0x" + tos.ToString("x") + ecn + ", ttl " + ttl + ", id " + id + ", offset " + ((ff & 0x1FFF) * 8) + ", flags [" + fl + "], proto " + ProtoName(proto) + ", length " + total);
            if (ihl > 20)
            {
                List<string> ops = new List<string>();
                for (int i = o + 20; i < o + ihl && i < d.Length; )
                {
                    int k = d[i];
                    if (k == 0) { ops.Add("EOL"); break; }
                    if (k == 1) { ops.Add("nop"); i++; continue; }
                    int l = i + 1 < d.Length ? d[i + 1] : 0;
                    if (l < 2) break;
                    ops.Add(k == 0x94 ? "RA" : k == 7 ? "RR" : k == 0x44 ? "TS" : "opt-" + k);
                    i += l;
                }
                h.Append(", options (" + string.Join(",", ops.ToArray()) + ")");
            }
            h.Append(")");
            string hs = h.ToString();
            lines.Add(head + hs);
            int end = Math.Min(o + total, d.Length);
            if (total == 0) end = d.Length;
            int poff = o + ihl;
            string prefix = "    ";
            if ((ff & 0x1FFF) != 0)
            {
                lines.Add(prefix + src + " > " + dst + ": ip-proto-" + proto);
                return;
            }
            Transport(d, poff, end, proto, src, dst, false, prefix, lines, total - ihl, o);
        }

        static string V6Proto(int p)
        {
            switch (p)
            {
                case 0: return "Options (0)"; case 6: return "TCP (6)"; case 17: return "UDP (17)"; case 43: return "Routing (43)"; case 44: return "Fragment (44)";
                case 58: return "ICMPv6 (58)"; case 59: return "No Next Header (59)"; case 60: return "Options (60)"; default: return "unknown (" + p + ")";
            }
        }

        static void Ipv6(byte[] d, int o, string head, List<string> lines)
        {
            uint vtf = U.L(d, o);
            int plen = U.W(d, o + 4), nh = d[o + 6], hlim = d[o + 7];
            string src = U.Ip6(d, o + 8), dst = U.Ip6(d, o + 24);
            int cls = (int)((vtf >> 20) & 0xFF); uint flow = vtf & 0xFFFFF;
            string h = "(" + (cls != 0 ? "class 0x" + cls.ToString("x") + ", " : "") + (flow != 0 ? "flowlabel 0x" + flow.ToString("x5") + ", " : "") +
                       "hlim " + hlim + ", next-header " + V6Proto(nh) + " payload length: " + plen + ") ";
            int poff = o + 40;
            int end = plen == 0 ? d.Length : Math.Min(poff + plen, d.Length);
            string ext = "";
            while ((nh == 0 || nh == 60) && poff + 8 <= end)
            {
                int hlen = (d[poff + 1] + 1) * 8;
                List<string> os = new List<string>();
                for (int i = poff + 2; i < poff + hlen && i < end; )
                {
                    int ot = d[i];
                    if (ot == 0) { os.Add("(pad1)"); i++; continue; }
                    int ol = i + 1 < end ? d[i + 1] : 0;
                    if (ot == 1) os.Add("(padn)");
                    else if (ot == 5 && ol >= 2) os.Add("(rtalert: 0x" + U.W(d, i + 2).ToString("x4") + ")");
                    else os.Add("(opt_type 0x" + ot.ToString("x2") + ": len=" + ol + ")");
                    i += 2 + ol;
                }
                ext += (nh == 0 ? "HBH " : "DSTOPT ") + string.Join(" ", os.ToArray()) + " ";
                nh = d[poff]; poff += hlen;
            }
            List<string> tmp = new List<string>();
            Transport(d, poff, end, nh, src, dst, true, "", tmp, plen, o);
            if (ext.Length > 0) { int k = tmp[0].IndexOf(dst + ": ") + dst.Length + 2; tmp[0] = tmp[0].Substring(0, k) + ext + tmp[0].Substring(k); }
            // IPv6 puts the first transport line on the same line as the header
            tmp[0] = head + h + tmp[0];
            lines.AddRange(tmp);
        }

        // ---------------------------------------------------------------- layer 4
        static void Transport(byte[] d, int o, int end, int proto, string src, string dst, bool v6, string prefix, List<string> lines, int l4len, int ipOff)
        {
            switch (proto)
            {
                case 6: lines.Add(prefix + Tcp(d, o, end, src, dst)); AppendHttp(d, o, end, lines); return;
                case 17: Udp(d, o, end, src, dst, prefix, lines); return;
                case 1: Icmp4(d, o, end, src, dst, prefix, lines, l4len); return;
                case 58: Icmp6(d, o, end, src, dst, prefix, lines, l4len, ipOff); return;
            }
            if (proto == 50) { lines.Add(prefix + src + " > " + dst + ":  [|esp]"); return; }
            lines.Add(prefix + src + " > " + dst + ": " + (v6 ? "" : " ") + "ip-proto-" + proto + " " + Math.Max(0, end - o));
        }

        static string TcpFlagText(int f)
        {
            StringBuilder sb = new StringBuilder();
            if ((f & 0x01) != 0) sb.Append('F'); if ((f & 0x02) != 0) sb.Append('S'); if ((f & 0x04) != 0) sb.Append('R'); if ((f & 0x08) != 0) sb.Append('P');
            if ((f & 0x10) != 0) sb.Append('.'); if ((f & 0x20) != 0) sb.Append('U'); if ((f & 0x40) != 0) sb.Append('E'); if ((f & 0x80) != 0) sb.Append('W');
            return sb.Length == 0 ? "none" : sb.ToString();
        }

        static string Tcp(byte[] d, int o, int end, string src, string dst)
        {
            int sport = U.W(d, o), dport = U.W(d, o + 2), hl = (d[o + 12] >> 4) * 4, fl = d[o + 13], win = U.W(d, o + 14), urg = U.W(d, o + 18);
            uint seq = U.L(d, o + 4), ack = U.L(d, o + 8);
            int len = Math.Max(0, end - o - hl);
            StringBuilder sb = new StringBuilder();
            sb.Append(src + "." + sport + " > " + dst + "." + dport + ": Flags [" + TcpFlagText(fl) + "], seq " + seq);
            if (len > 0) sb.Append(":" + (uint)(seq + (uint)len));
            if ((fl & 0x10) != 0) sb.Append(", ack " + ack);
            sb.Append(", win " + win);
            if ((fl & 0x20) != 0) sb.Append(", urg " + urg);
            if (hl > 20)
            {
                List<string> ops = new List<string>();
                int i = o + 20, oe = Math.Min(o + hl, d.Length);
                while (i < oe)
                {
                    int k = d[i];
                    if (k == 0) { ops.Add("eol"); break; }
                    if (k == 1) { ops.Add("nop"); i++; continue; }
                    if (i + 1 >= oe) break;
                    int l = d[i + 1];
                    if (l < 2 || i + l > oe) break;
                    switch (k)
                    {
                        case 2: ops.Add("mss " + U.W(d, i + 2)); break;
                        case 3: ops.Add("wscale " + d[i + 2]); break;
                        case 4: ops.Add("sackOK"); break;
                        case 5:
                            {
                                StringBuilder sk = new StringBuilder("sack " + ((l - 2) / 8));
                                for (int b = 0; b + 8 <= l - 2; b += 8) sk.Append((b == 0 ? " " : "") + "{" + U.L(d, i + 2 + b) + ":" + U.L(d, i + 6 + b) + "}");
                                ops.Add(sk.ToString()); break;
                            }
                        case 8: ops.Add("TS val " + U.L(d, i + 2) + " ecr " + U.L(d, i + 6)); break;
                        default: ops.Add("unknown-" + k); break;
                    }
                    i += l;
                }
                sb.Append(", options [" + string.Join(",", ops.ToArray()) + "]");
            }
            sb.Append(", length " + len);
            int po = o + hl;
            if (len > 0)
            {
                bool http = IsHttp(d, po, end);
                if (http) sb.Append(": HTTP, length: " + len);
                else if (sport == 80 || dport == 80 || sport == 8080 || dport == 8080) sb.Append(": HTTP");
            }
            return sb.ToString();
        }

        static bool IsHttp(byte[] d, int o, int end)
        {
            string[] m = { "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ", "HTTP/1." };
            foreach (string s in m)
            {
                if (end - o < s.Length) continue;
                bool ok = true;
                for (int i = 0; i < s.Length; i++) if (d[o + i] != (byte)s[i]) { ok = false; break; }
                if (ok) return true;
            }
            return false;
        }

        // the HTTP text of a segment, one tab-indented line per line of text
        static void AppendHttp(byte[] d, int o, int end, List<string> lines)
        {
            int hl = (d[o + 12] >> 4) * 4, po = o + hl;
            if (po >= end || !IsHttp(d, po, end)) return;
            StringBuilder cur = new StringBuilder();
            bool stopped = false;
            for (int i = po; i < end; i++)
            {
                byte b = d[i];
                if (b == 13) continue;
                if (b == 10) { lines.Add("\t" + cur.ToString()); cur.Length = 0; continue; }
                if (b < 32 && b != 9 || b > 126) { stopped = true; break; }
                cur.Append((char)b);
            }
            if (cur.Length > 0) lines.Add("\t" + cur.ToString() + (stopped ? "" : "[!http]"));
        }

        static void Udp(byte[] d, int o, int end, string src, string dst, string prefix, List<string> lines)
        {
            int sport = U.W(d, o), dport = U.W(d, o + 2), ulen = U.W(d, o + 4);
            int po = o + 8, pend = ulen >= 8 ? Math.Min(o + ulen, end) : end;
            string head = prefix + src + "." + sport + " > " + dst + "." + dport + ": ";
            string dns = null;
            if ((sport == 53 || dport == 53 || sport == 5353 || dport == 5353) && pend - po >= 12)
            {
                try { dns = Dns(d, po, pend, sport == 5353 || dport == 5353); } catch (IndexOutOfRangeException) { dns = null; } catch (ArgumentException) { dns = null; }
            }
            lines.Add(head + (dns ?? "UDP, length " + Math.Max(0, ulen - 8)));
        }

        // ---------------------------------------------------------------- DNS (tcpdump style)
        static string DnsType(int t)
        {
            switch (t)
            {
                case 1: return "A"; case 2: return "NS"; case 5: return "CNAME"; case 6: return "SOA"; case 12: return "PTR"; case 15: return "MX";
                case 16: return "TXT"; case 28: return "AAAA"; case 33: return "SRV"; case 41: return "OPT"; case 255: return "ANY"; case 65: return "HTTPS";
                default: return "Type" + t;
            }
        }

        static string DName(byte[] d, int msg, ref int pos)
        {
            StringBuilder sb = new StringBuilder();
            int p = pos, after = -1, guard = 0;
            while (guard++ < 128)
            {
                int l = d[p];
                if (l == 0) { p++; break; }
                if ((l & 0xC0) == 0xC0) { int ptr = ((l & 0x3F) << 8) | d[p + 1]; if (after < 0) after = p + 2; p = msg + ptr; continue; }
                p++; sb.Append(Encoding.ASCII.GetString(d, p, l)).Append('.'); p += l;
            }
            pos = after >= 0 ? after : p;
            return sb.Length == 0 ? "." : sb.ToString();
        }

        static string Ttl(uint s)
        {
            if (s == 0) return "0s";
            StringBuilder sb = new StringBuilder();
            uint dd = s / 86400, hh = (s % 86400) / 3600, mm = (s % 3600) / 60, ss = s % 60;
            if (dd > 0) sb.Append(dd + "d"); if (hh > 0) sb.Append(hh + "h"); if (mm > 0) sb.Append(mm + "m"); if (ss > 0) sb.Append(ss + "s");
            return sb.ToString();
        }

        static string Rr(byte[] d, int msg, ref int pos, bool mdns)
        {
            string name = DName(d, msg, ref pos);
            int type = U.W(d, pos), cls = U.W(d, pos + 2);
            uint ttl = U.L(d, pos + 4); int rdl = U.W(d, pos + 8);
            pos += 10;
            int rp = pos;
            string data;
            switch (type)
            {
                case 1: data = " " + U.Ip4(d, rp); break;
                case 28: data = " " + U.Ip6(d, rp); break;
                case 2: case 5: case 12: data = " " + DName(d, msg, ref rp); break;
                case 15: { int pref = U.W(d, rp); rp += 2; data = " " + DName(d, msg, ref rp) + " " + pref; break; }
                case 16: { StringBuilder t = new StringBuilder(); int q = rp; while (q < rp + rdl) { int l = d[q]; t.Append(" \"" + Encoding.ASCII.GetString(d, q + 1, Math.Min(l, d.Length - q - 1)) + "\""); q += 1 + l; } data = t.ToString(); break; }
                case 6:
                    {
                        string m = DName(d, msg, ref rp), r = DName(d, msg, ref rp);
                        data = " " + m + " " + r + " " + U.L(d, rp) + " " + U.L(d, rp + 4) + " " + U.L(d, rp + 8) + " " + U.L(d, rp + 12) + " " + U.L(d, rp + 16); break;
                    }
                case 33: { int pr = U.W(d, rp), w = U.W(d, rp + 2), po = U.W(d, rp + 4); rp += 6; data = " " + DName(d, msg, ref rp) + ":" + po + " " + pr + " " + w; break; }
                case 41: data = ""; break;
                default: data = " " + rdl + " bytes"; break;
            }
            pos += rdl;
            if (type == 41) return "OPT";
            return name + " " + (mdns && (cls & 0x8000) != 0 ? "(Cache flush) " : "") + "[" + Ttl(ttl) + "] " + DnsType(type) + data;
        }

        static string Dns(byte[] d, int o, int end, bool mdns)
        {
            int id = U.W(d, o), fl = U.W(d, o + 2), qd = U.W(d, o + 4), an = U.W(d, o + 6), ns = U.W(d, o + 8), ar = U.W(d, o + 10);
            bool resp = (fl & 0x8000) != 0;
            int opcode = (fl >> 11) & 0xF, rcode = fl & 0xF;
            string[] rc = { "", " FormErr", " ServFail", " NXDomain", " NotImp", " Refused", " YXDomain", " YXRRSet", " NXRRSet", " NotAuth", " NotZone" };
            int pos = o + 12;
            StringBuilder sb = new StringBuilder();
            sb.Append(id);
            string ops = opcode == 0 ? "" : opcode == 1 ? " inv" : opcode == 2 ? " stat" : opcode == 4 ? " notify" : opcode == 5 ? " update" : " op" + opcode;
            if (!resp)
            {
                sb.Append(ops);
                if ((fl & 0x100) != 0) sb.Append('+');
                if ((fl & 0x20) != 0) sb.Append('$');
                if ((fl & 0x10) != 0) sb.Append('%');
                if (an > 0) sb.Append(" [" + an + "a]");
                if (ns > 0) sb.Append(" [" + ns + "n]");
                if (ar > 0) sb.Append(" [" + ar + "au]");
                List<string> qs = new List<string>();
                for (int i = 0; i < qd; i++)
                {
                    string qn = DName(d, o, ref pos);
                    int qt = U.W(d, pos), qc = U.W(d, pos + 2); pos += 4;
                    qs.Add(DnsType(qt) + (mdns ? ((qc & 0x8000) != 0 ? " (QU)" : " (QM)") : "") + "? " + qn);
                }
                sb.Append(" " + string.Join(", ", qs.ToArray()));
                sb.Append(" (" + (end - o) + ")");
                return sb.ToString();
            }
            sb.Append(ops + (rcode < rc.Length ? rc[rcode] : " rcode" + rcode));
            if ((fl & 0x400) != 0) sb.Append('*');
            if ((fl & 0x80) == 0) sb.Append('-');
            if ((fl & 0x20) != 0) sb.Append('$');
            if ((fl & 0x10) != 0) sb.Append('%');
            List<string> ql = new List<string>();
            for (int i = 0; i < qd; i++)
            {
                string qn = DName(d, o, ref pos);
                int qt = U.W(d, pos); pos += 4;
                ql.Add(DnsType(qt) + "? " + qn);
            }
            if (ql.Count > 0) sb.Append(" q: " + string.Join(", ", ql.ToArray()));
            sb.Append(" " + an + "/" + ns + "/" + ar);
            for (int sec = 0; sec < 3; sec++)
            {
                int cnt = sec == 0 ? an : sec == 1 ? ns : ar;
                List<string> rs = new List<string>();
                for (int i = 0; i < cnt; i++) rs.Add(Rr(d, o, ref pos, mdns));
                if (rs.Count > 0) sb.Append((sec == 0 ? " " : sec == 1 ? " ns: " : " ar: ") + string.Join(", ", rs.ToArray()));
            }
            sb.Append(" (" + (end - o) + ")");
            return sb.ToString();
        }

        // ---------------------------------------------------------------- ICMP
        static void Icmp4(byte[] d, int o, int end, string src, string dst, string prefix, List<string> lines, int l4len)
        {
            int t = d[o], code = d[o + 1];
            string head = prefix + src + " > " + dst + ": ICMP ";
            int len = Math.Max(0, end - o);
            string text;
            bool inner = false;
            switch (t)
            {
                case 0: text = "echo reply, id " + U.W(d, o + 4) + ", seq " + U.W(d, o + 6) + ", length " + len; break;
                case 8: text = "echo request, id " + U.W(d, o + 4) + ", seq " + U.W(d, o + 6) + ", length " + len; break;
                case 3:
                    {
                        inner = true;
                        int io = o + 8;
                        string idst = end - io >= 20 ? U.Ip4(d, io + 16) : "?";
                        int ip = end - io >= 20 ? d[io + 9] : 0;
                        int ihl = end - io >= 20 ? (d[io] & 0xF) * 4 : 20;
                        switch (code)
                        {
                            case 0: text = "net " + idst + " unreachable"; break;
                            case 1: text = "host " + idst + " unreachable"; break;
                            case 2: text = idst + " protocol " + ip + " unreachable"; break;
                            case 3:
                                {
                                    string pn = ip == 17 ? "udp" : ip == 6 ? "tcp" : "ip-proto-" + ip;
                                    int port = end - io >= ihl + 4 ? U.W(d, io + ihl + 2) : 0;
                                    text = idst + " " + pn + " port " + port + " unreachable"; break;
                                }
                            case 4: text = idst + " unreachable - need to frag (mtu " + U.W(d, o + 6) + ")"; break;
                            case 5: text = "net " + idst + " unreachable"; break;
                            case 13: text = idst + " unreachable - admin prohibited filter"; break;
                            default: text = idst + " unreachable, code " + code; break;
                        }
                        text += ", length " + len; break;
                    }
                case 11: inner = true; text = "time exceeded in-transit, length " + len; break;
                case 5:
                    {
                        inner = true;
                        int io5 = o + 8;
                        string rd = end - io5 >= 20 ? U.Ip4(d, io5 + 16) : "?";
                        string[] rk = { "net", "host", "tos net", "tos host" };
                        text = "redirect " + rd + " to " + (code < 4 ? rk[code] : "code " + code) + " " + U.Ip4(d, o + 4) + ", length " + len; break;
                    }
                default: text = "type-#" + t + ", length " + len; break;
            }
            ushort calc = U.Csum(d, o, end - o);
            if (calc != 0)
            {
                int given = U.W(d, o + 2);
                d[o + 2] = 0; d[o + 3] = 0;                                  // restore afterwards
                int want = U.Csum(d, o, end - o);
                d[o + 2] = (byte)(given >> 8); d[o + 3] = (byte)given;
                text += " (wrong icmp cksum " + given.ToString("x") + " (->" + want.ToString("x") + ")!)";
            }
            lines.Add(head + text);
            if (inner && end - (o + 8) >= 20)
            {
                int io = o + 8;
                List<string> il = new List<string>();
                try { Ipv4(d, io, "", il); } catch (IndexOutOfRangeException) { } catch (ArgumentException) { }
                if (il.Count > 0) { lines.Add("\t" + il[0]); for (int i = 1; i < il.Count; i++) lines.Add(il[i]); }
            }
        }

        static ushort Icmp6Sum(byte[] d, int o, int end, int ipOff)
        {
            // pseudo header: src, dst, upper-layer length, next header 58
            int len = end - o;
            uint sum = 0;
            for (int i = 0; i < 32; i += 2) sum += (uint)((d[ipOff + 8 + i] << 8) | d[ipOff + 8 + i + 1]);
            sum += (uint)len; sum += 58;
            int j = 0;
            for (; j + 1 < len; j += 2) sum += (uint)((d[o + j] << 8) | d[o + j + 1]);
            if (j < len) sum += (uint)(d[o + j] << 8);
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)(~sum & 0xFFFF);
        }

        static void Icmp6(byte[] d, int o, int end, string src, string dst, string prefix, List<string> lines, int l4len, int ipOff)
        {
            int t = d[o], code = d[o + 1], len = end - o;
            bool sumOk = ipOff >= 0 && Icmp6Sum(d, o, end, ipOff) == 0;
            string sumText = "[icmp6 sum ok] ";
            if (!sumOk)
            {
                int given = U.W(d, o + 2);
                d[o + 2] = 0; d[o + 3] = 0;
                int want = ipOff >= 0 ? Icmp6Sum(d, o, end, ipOff) : 0;
                d[o + 2] = (byte)(given >> 8); d[o + 3] = (byte)given;
                sumText = "[bad icmp6 cksum " + U.Hx(given, 4) + " -> " + U.Hx(want, 4) + "!] ";
            }
            string head = prefix + src + " > " + dst + ": " + sumText + "ICMP6, ";
            string text;
            string raLine = null;
            int optStart = -1;
            switch (t)
            {
                case 128: text = "echo request, seq " + U.W(d, o + 6); break;
                case 129: text = "echo reply, seq " + U.W(d, o + 6); break;
                case 133: text = "router solicitation, length " + len; optStart = o + 8; break;
                case 134:
                    {
                        int ra = d[o + 5];
                        List<string> rf = new List<string>();
                        if ((ra & 0x80) != 0) rf.Add("managed"); if ((ra & 0x40) != 0) rf.Add("other stateful"); if ((ra & 0x20) != 0) rf.Add("home agent");
                        int pr = (ra >> 3) & 3;
                        text = "router advertisement, length " + len; optStart = o + 16;
                        raLine = "\thop limit " + d[o + 4] + ", Flags [" + (rf.Count == 0 ? "none" : string.Join(", ", rf.ToArray())) + "], pref " + (pr == 0 ? "medium" : pr == 1 ? "high" : pr == 3 ? "low" : "rsvd") +
                                 ", router lifetime " + U.W(d, o + 6) + "s, reachable time " + U.L(d, o + 8) + "ms, retrans timer " + U.L(d, o + 12) + "ms";
                        break;
                    }
                case 135: text = "neighbor solicitation, length " + len + ", who has " + U.Ip6(d, o + 8); optStart = o + 24; break;
                case 136:
                    {
                        uint f = U.L(d, o + 4);
                        List<string> fl = new List<string>();
                        if ((f & 0x80000000) != 0) fl.Add("router"); if ((f & 0x40000000) != 0) fl.Add("solicited"); if ((f & 0x20000000) != 0) fl.Add("override");
                        text = "neighbor advertisement, length " + len + ", tgt is " + U.Ip6(d, o + 8) + (fl.Count > 0 ? ", Flags [" + string.Join(", ", fl.ToArray()) + "]" : ", Flags [none]");
                        optStart = o + 24; break;
                    }
                case 130: text = "multicast listener query v2, length " + len; break;
                case 143:
                    {
                        int n = U.W(d, o + 6), ro = o + 8;
                        StringBuilder rs = new StringBuilder();
                        string[] rt = { "", "is_in", "is_ex", "to_in", "to_ex", "allow", "block" };
                        for (int i = 0; i < n && ro + 20 <= end; i++)
                        {
                            int ty = d[ro], aux = d[ro + 1], ns = U.W(d, ro + 2);
                            StringBuilder srcs = new StringBuilder();
                            for (int k = 0; k < ns && ro + 20 + k * 16 + 16 <= end; k++) srcs.Append(U.Ip6(d, ro + 20 + k * 16) + " ");
                            rs.Append(" [gaddr " + U.Ip6(d, ro + 4) + " " + (ty < rt.Length ? rt[ty] : "type" + ty) + " { " + srcs.ToString() + "}]");
                            ro += 20 + ns * 16 + aux * 4;
                        }
                        text = "multicast listener report v2, " + n + " group record(s)" + rs.ToString(); break;
                    }
                case 1: text = "destination unreachable, length " + len; break;
                case 3: text = "time exceeded in-transit, length " + len; break;
                default: text = "type-#" + t + ", length " + len; break;
            }
            lines.Add(head + text);
            if (raLine != null) lines.Add(raLine);
            if (optStart > 0)
            {
                int i = optStart;
                while (i + 2 <= end && i + 2 <= d.Length)
                {
                    int ot = d[i], ol = d[i + 1];
                    if (ol == 0 || i + ol * 8 > end) break;
                    string oname = ot == 1 ? "source link-address" : ot == 2 ? "destination link-address" : ot == 5 ? "mtu" : ot == 3 ? "prefix info" : ot == 25 ? "rdnss" : ot == 31 ? "dnssl" : ot == 7 ? "advertisement interval" : "type-" + ot;
                    string oh = "\t  " + oname + " option (" + ot + "), length " + (ol * 8) + " (" + ol + ")";
                    if (ot == 1 || ot == 2) oh += ": " + U.Mac(d, i + 2);
                    else if (ot == 5) oh += ":  " + U.L(d, i + 4);
                    else if (ot == 3)
                    {
                        int pf = d[i + 3];
                        List<string> pfl = new List<string>();
                        if ((pf & 0x80) != 0) pfl.Add("onlink"); if ((pf & 0x40) != 0) pfl.Add("auto"); if ((pf & 0x20) != 0) pfl.Add("router");
                        uint vt = U.L(d, i + 4), pt = U.L(d, i + 8);
                        oh += ": " + U.Ip6(d, i + 16) + "/" + d[i + 2] + ", Flags [" + string.Join(", ", pfl.ToArray()) + "], valid time " + (vt == 0xFFFFFFFF ? "infinity" : vt + "s") + ", pref. time " + (pt == 0xFFFFFFFF ? "infinity" : pt + "s");
                    }
                    else if (ot == 25)
                    {
                        StringBuilder ad = new StringBuilder();
                        for (int a = i + 8; a + 16 <= i + ol * 8; a += 16) ad.Append((ad.Length > 0 ? ", " : "") + U.Ip6(d, a));
                        oh += ":  lifetime " + U.L(d, i + 4) + "s, addr: " + ad;
                    }
                    else if (ot == 31)
                    {
                        StringBuilder dm = new StringBuilder();
                        int a = i + 8;
                        while (a < i + ol * 8 && d[a] != 0)
                        {
                            StringBuilder nm = new StringBuilder();
                            while (a < i + ol * 8 && d[a] != 0) { int l = d[a]; nm.Append(Encoding.ASCII.GetString(d, a + 1, Math.Min(l, d.Length - a - 1))).Append('.'); a += 1 + l; }
                            dm.Append((dm.Length > 0 ? " " : "") + nm); a++;
                        }
                        oh += ":  lifetime " + U.L(d, i + 4) + "s, domain(s): " + dm;
                    }
                    else if (ot == 7) oh += ":  " + U.L(d, i + 4) + "ms";
                    lines.Add(oh);
                    HexLines(d, i + 2, i + ol * 8, lines, "\t    ");
                    i += ol * 8;
                }
            }
        }

        // ---------------------------------------------------------------- hex dump lines (tcpdump -x style)
        static void HexLines(byte[] d, int o, int end, List<string> lines) { HexLines(d, o, end, lines, "\t"); }
        static void HexLines(byte[] d, int o, int end, List<string> lines, string indent)
        {
            for (int r = 0; o + r < end; r += 16)
            {
                StringBuilder sb = new StringBuilder(indent + "0x" + r.ToString("x4") + ": ");
                for (int i = 0; i < 16 && o + r + i < end; i++)
                {
                    if (i % 2 == 0) sb.Append(' ');
                    sb.Append(d[o + r + i].ToString("x2"));
                }
                lines.Add(sb.ToString());
            }
        }

        // ---------------------------------------------------------------- writer (runs on a worker runspace)
        public static void Write(string path, IList<Packet> pkts, SharedState st)
        {
            try
            {
                st.Total = pkts.Count;
                using (StreamWriter w = new StreamWriter(path, false, new UTF8Encoding(false), 1 << 16))
                {
                    w.NewLine = "\r\n";
                    for (int i = 0; i < pkts.Count; i++)
                    {
                        if (st.Cancel) break;
                        Packet p = pkts[i];
                        w.WriteLine(Header(p, p.No));
                        foreach (string ln in Decode(p))
                            foreach (string part in ln.Split('\n')) w.WriteLine("\t" + part);
                        st.Progress = i + 1;
                    }
                }
            }
            catch (Exception ex) { st.Error = ex.Message; }
            finally { st.Done = true; }
        }
    }
}

// ==== PKTMON-TEXT-END

'@
# Compiled types cannot be unloaded, so a session that already ran an older PSShark would keep
# the old code. Detect that (by hash of the embedded source) and restart in a fresh process.
$script:coreHash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($script:csharp))).Replace('-', '').Substring(0, 16)
if (-not ('PSShark.Dissector' -as [type])) {
    Add-Type -TypeDefinition $script:csharp -Language CSharp
    [AppDomain]::CurrentDomain.SetData('PSSharkCoreHash', $script:coreHash)
}
elseif ([AppDomain]::CurrentDomain.GetData('PSSharkCoreHash') -ne $script:coreHash) {
    Write-Warning 'This PowerShell session still holds an older PSShark build; restarting PSShark in a fresh process.'
    & (Get-Process -Id $PID).Path -NoProfile -STA -ExecutionPolicy Bypass -File $PSCommandPath @fwd
    return
}

############################################################################
# XAML: shared styles (same palette as PSPigeon: #181735 window, #0F0F4D title,
# #552284 buttons, #FF4C70 hover, Cyan/Yellow/Lime accents)
############################################################################
$script:stylesXaml = @'
<Window.Resources>
    <SolidColorBrush x:Key="{x:Static SystemColors.ControlBrushKey}" Color="#0F0F4D"/>

    <!-- Scroll bars -->
    <Style x:Key="ScrollThumb" TargetType="Thumb">
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="Thumb">
                    <Border x:Name="b" Background="#552284" CornerRadius="5" Margin="2"/>
                    <ControlTemplate.Triggers>
                        <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#FF4C70"/></Trigger>
                        <Trigger Property="IsDragging" Value="True"><Setter TargetName="b" Property="Background" Value="#FF4C70"/></Trigger>
                    </ControlTemplate.Triggers>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>
    <Style x:Key="ScrollPage" TargetType="RepeatButton">
        <Setter Property="Focusable" Value="False"/>
        <Setter Property="IsTabStop" Value="False"/>
        <Setter Property="Template">
            <Setter.Value><ControlTemplate TargetType="RepeatButton"><Border Background="Transparent"/></ControlTemplate></Setter.Value>
        </Setter>
    </Style>
    <ControlTemplate x:Key="VScrollT" TargetType="ScrollBar">
        <Grid Background="#0F0F4D">
            <Track x:Name="PART_Track" IsDirectionReversed="True">
                <Track.DecreaseRepeatButton><RepeatButton Style="{StaticResource ScrollPage}" Command="ScrollBar.PageUpCommand"/></Track.DecreaseRepeatButton>
                <Track.Thumb><Thumb Style="{StaticResource ScrollThumb}"/></Track.Thumb>
                <Track.IncreaseRepeatButton><RepeatButton Style="{StaticResource ScrollPage}" Command="ScrollBar.PageDownCommand"/></Track.IncreaseRepeatButton>
            </Track>
        </Grid>
    </ControlTemplate>
    <ControlTemplate x:Key="HScrollT" TargetType="ScrollBar">
        <Grid Background="#0F0F4D">
            <Track x:Name="PART_Track" IsDirectionReversed="False">
                <Track.DecreaseRepeatButton><RepeatButton Style="{StaticResource ScrollPage}" Command="ScrollBar.PageLeftCommand"/></Track.DecreaseRepeatButton>
                <Track.Thumb><Thumb Style="{StaticResource ScrollThumb}"/></Track.Thumb>
                <Track.IncreaseRepeatButton><RepeatButton Style="{StaticResource ScrollPage}" Command="ScrollBar.PageRightCommand"/></Track.IncreaseRepeatButton>
            </Track>
        </Grid>
    </ControlTemplate>
    <Style TargetType="ScrollViewer">
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="ScrollViewer">
                    <Grid Background="{TemplateBinding Background}">
                        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                        <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                        <ScrollContentPresenter x:Name="PART_ScrollContentPresenter" Grid.Column="0" Grid.Row="0" CanContentScroll="{TemplateBinding CanContentScroll}" Margin="{TemplateBinding Padding}"/>
                        <Rectangle Grid.Column="1" Grid.Row="1" Fill="#0F0F4D"/>
                        <ScrollBar x:Name="PART_VerticalScrollBar" Grid.Column="1" Grid.Row="0" Orientation="Vertical" Maximum="{TemplateBinding ScrollableHeight}" ViewportSize="{TemplateBinding ViewportHeight}" Value="{TemplateBinding VerticalOffset}" Visibility="{TemplateBinding ComputedVerticalScrollBarVisibility}" Cursor="Arrow"/>
                        <ScrollBar x:Name="PART_HorizontalScrollBar" Grid.Column="0" Grid.Row="1" Orientation="Horizontal" Maximum="{TemplateBinding ScrollableWidth}" ViewportSize="{TemplateBinding ViewportWidth}" Value="{TemplateBinding HorizontalOffset}" Visibility="{TemplateBinding ComputedHorizontalScrollBarVisibility}" Cursor="Arrow"/>
                    </Grid>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>
    <Style TargetType="ScrollBar">
        <Setter Property="Template" Value="{StaticResource VScrollT}"/>
        <Setter Property="Width" Value="14"/>
        <Style.Triggers>
            <Trigger Property="Orientation" Value="Horizontal">
                <Setter Property="Template" Value="{StaticResource HScrollT}"/>
                <Setter Property="Width" Value="Auto"/>
                <Setter Property="Height" Value="14"/>
            </Trigger>
        </Style.Triggers>
    </Style>

    <!-- Buttons -->
    <Style x:Key="PurpleBtn" TargetType="Button">
        <Setter Property="Background" Value="#552284"/>
        <Setter Property="Foreground" Value="Cyan"/>
        <Setter Property="FontWeight" Value="Medium"/>
        <Setter Property="Padding" Value="16,4"/>
        <Setter Property="Cursor" Value="Hand"/>
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="Button">
                    <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="12" Padding="{TemplateBinding Padding}">
                        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <ControlTemplate.Triggers>
                        <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#FF4C70"/></Trigger>
                        <Trigger Property="IsEnabled" Value="False">
                            <Setter TargetName="b" Property="Background" Value="#2A2A55"/>
                            <Setter Property="Foreground" Value="#777799"/>
                        </Trigger>
                    </ControlTemplate.Triggers>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>
    <Style x:Key="ToolBtn" TargetType="Button">
        <Setter Property="Background" Value="Transparent"/>
        <Setter Property="Foreground" Value="Cyan"/>
        <Setter Property="FontFamily" Value="Segoe MDL2 Assets"/>
        <Setter Property="FontSize" Value="15"/>
        <Setter Property="Width" Value="30"/>
        <Setter Property="Height" Value="28"/>
        <Setter Property="Margin" Value="1,0"/>
        <Setter Property="Cursor" Value="Hand"/>
        <Setter Property="Focusable" Value="False"/>
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="Button">
                    <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="6">
                        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <ControlTemplate.Triggers>
                        <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#552284"/></Trigger>
                        <Trigger Property="IsPressed" Value="True"><Setter TargetName="b" Property="Background" Value="#FF4C70"/></Trigger>
                        <Trigger Property="IsEnabled" Value="False"><Setter Property="Foreground" Value="#4A4A78"/></Trigger>
                    </ControlTemplate.Triggers>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>
    <Style x:Key="ToolToggle" TargetType="ToggleButton">
        <Setter Property="Foreground" Value="Cyan"/>
        <Setter Property="FontFamily" Value="Segoe MDL2 Assets"/>
        <Setter Property="FontSize" Value="15"/>
        <Setter Property="Width" Value="30"/>
        <Setter Property="Height" Value="28"/>
        <Setter Property="Margin" Value="1,0"/>
        <Setter Property="Cursor" Value="Hand"/>
        <Setter Property="Focusable" Value="False"/>
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="ToggleButton">
                    <Border x:Name="b" Background="Transparent" CornerRadius="6">
                        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <ControlTemplate.Triggers>
                        <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#3A1A60"/></Trigger>
                        <Trigger Property="IsChecked" Value="True"><Setter TargetName="b" Property="Background" Value="#552284"/></Trigger>
                    </ControlTemplate.Triggers>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>

    <!-- Menus -->
    <Style TargetType="Menu">
        <Setter Property="Background" Value="#0F0F4D"/>
        <Setter Property="Foreground" Value="#E8E8FF"/>
        <Setter Property="FontSize" Value="13"/>
    </Style>
    <Style x:Key="{x:Static MenuItem.SeparatorStyleKey}" TargetType="Separator">
        <Setter Property="Height" Value="1"/>
        <Setter Property="Margin" Value="6,3"/>
        <Setter Property="Template">
            <Setter.Value><ControlTemplate TargetType="Separator"><Border Background="#552284" Height="1"/></ControlTemplate></Setter.Value>
        </Setter>
    </Style>
    <Style TargetType="MenuItem">
        <Setter Property="Foreground" Value="#E8E8FF"/>
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="MenuItem">
                    <Border x:Name="Bd" Background="Transparent" Padding="10,5" SnapsToDevicePixels="True">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <TextBlock x:Name="Chk" Grid.Column="0" Text="&#x2714;" FontFamily="Segoe UI Symbol" FontSize="11" Width="22" Foreground="Lime" Visibility="Hidden" VerticalAlignment="Center"/>
                            <ContentPresenter Grid.Column="1" ContentSource="Header" RecognizesAccessKey="True" VerticalAlignment="Center"/>
                            <TextBlock x:Name="Gest" Grid.Column="2" Text="{TemplateBinding InputGestureText}" Margin="28,0,0,0" Foreground="#9FA3D6" VerticalAlignment="Center"/>
                            <TextBlock x:Name="Arr" Grid.Column="3" Text="&#x25B6;" FontSize="8" Margin="10,0,0,0" Foreground="Cyan" Visibility="Collapsed" VerticalAlignment="Center"/>
                            <Popup x:Name="PART_Popup" Placement="Bottom" IsOpen="{TemplateBinding IsSubmenuOpen}" AllowsTransparency="False" Focusable="False" PopupAnimation="None">
                                <Border Background="#0F0F4D" BorderBrush="#552284" BorderThickness="1">
                                    <StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Cycle" Margin="0,2"/>
                                </Border>
                            </Popup>
                        </Grid>
                    </Border>
                    <ControlTemplate.Triggers>
                        <Trigger Property="Role" Value="TopLevelHeader">
                            <Setter TargetName="Chk" Property="Visibility" Value="Collapsed"/>
                            <Setter TargetName="Gest" Property="Visibility" Value="Collapsed"/>
                            <Setter TargetName="Bd" Property="Padding" Value="10,4"/>
                        </Trigger>
                        <Trigger Property="Role" Value="SubmenuHeader">
                            <Setter TargetName="Arr" Property="Visibility" Value="Visible"/>
                            <Setter TargetName="PART_Popup" Property="Placement" Value="Right"/>
                        </Trigger>
                        <Trigger Property="IsChecked" Value="True"><Setter TargetName="Chk" Property="Visibility" Value="Visible"/></Trigger>
                        <Trigger Property="IsHighlighted" Value="True"><Setter TargetName="Bd" Property="Background" Value="#552284"/></Trigger>
                        <Trigger Property="IsEnabled" Value="False"><Setter Property="Foreground" Value="#5A5A8A"/></Trigger>
                    </ControlTemplate.Triggers>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>

    <Style TargetType="ContextMenu">
        <Setter Property="Foreground" Value="#E8E8FF"/>
        <Setter Property="FontSize" Value="13"/>
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="ContextMenu">
                    <Border Background="#0F0F4D" BorderBrush="#552284" BorderThickness="1" Padding="0,2">
                        <StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Cycle"/>
                    </Border>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>

    <!-- Inputs -->
    <Style TargetType="TextBox">
        <Setter Property="Background" Value="#0F0F4D"/>
        <Setter Property="Foreground" Value="White"/>
        <Setter Property="CaretBrush" Value="White"/>
        <Setter Property="BorderBrush" Value="#552284"/>
        <Setter Property="SelectionBrush" Value="#FF4C70"/>
        <Setter Property="Padding" Value="4,3"/>
    </Style>
    <Style TargetType="CheckBox"><Setter Property="Foreground" Value="#E8E8FF"/></Style>
    <Style TargetType="TextBlock" x:Key="CellText"><Setter Property="Padding" Value="6,0,6,0"/><Setter Property="VerticalAlignment" Value="Center"/></Style>
    <Style TargetType="TextBlock" x:Key="CellTextR" BasedOn="{StaticResource CellText}"><Setter Property="TextAlignment" Value="Right"/></Style>

    <!-- Data grids -->
    <Style TargetType="DataGridColumnHeader">
        <Setter Property="Background" Value="#0F0F4D"/>
        <Setter Property="Foreground" Value="Cyan"/>
        <Setter Property="BorderBrush" Value="#2E2C6B"/>
        <Setter Property="BorderThickness" Value="0,0,1,1"/>
        <Setter Property="Padding" Value="6,3"/>
        <Setter Property="FontWeight" Value="SemiBold"/>
        <Setter Property="HorizontalContentAlignment" Value="Left"/>
    </Style>
    <Style TargetType="DataGridCell">
        <Setter Property="Background" Value="Transparent"/>
        <Setter Property="BorderThickness" Value="0"/>
        <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="DataGridCell">
                    <Border Background="Transparent" SnapsToDevicePixels="True"><ContentPresenter VerticalAlignment="Center"/></Border>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>
    <Style x:Key="RowColor" TargetType="DataGridRow">
        <Setter Property="Background" Value="{Binding Bg}"/>
        <Setter Property="Foreground" Value="{Binding Fg}"/>
        <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
        <Style.Triggers>
            <Trigger Property="IsSelected" Value="True">
                <Setter Property="Background" Value="#552284"/>
                <Setter Property="Foreground" Value="White"/>
            </Trigger>
        </Style.Triggers>
    </Style>
    <Style x:Key="RowPlain" TargetType="DataGridRow">
        <Setter Property="Background" Value="Transparent"/>
        <Setter Property="Foreground" Value="#E8E8FF"/>
        <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
        <Style.Triggers>
            <Trigger Property="IsSelected" Value="True">
                <Setter Property="Background" Value="#552284"/>
                <Setter Property="Foreground" Value="White"/>
            </Trigger>
            <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#2A1A55"/></Trigger>
        </Style.Triggers>
    </Style>
</Window.Resources>
'@

############################################################################
# XAML: main window
############################################################################
$script:mainBody = @'
<shell:WindowChrome.WindowChrome>
    <shell:WindowChrome CaptionHeight="34" ResizeBorderThickness="{x:Static SystemParameters.WindowResizeBorderThickness}" GlassFrameThickness="0" CornerRadius="0" UseAeroCaptionButtons="False"/>
</shell:WindowChrome.WindowChrome>
<Border x:Name="rootBorder" Background="#181735" BorderBrush="#552284" BorderThickness="1">
<Grid>
    <Grid.RowDefinitions>
        <RowDefinition Height="34"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="*"/>
        <RowDefinition Height="26"/>
    </Grid.RowDefinitions>

    <!-- Title bar -->
    <Grid x:Name="gTitle" Grid.Row="0" Background="#0F0F4D">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="42"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Image x:Name="imgLogo" Grid.Column="0" Width="24" Height="24" HorizontalAlignment="Center" VerticalAlignment="Center" RenderOptions.BitmapScalingMode="HighQuality"/>
        <TextBlock Grid.Column="1" Text="PSShark" Foreground="Yellow" FontSize="18" FontWeight="Bold" FontFamily="Courier New" VerticalAlignment="Center"/>
        <TextBlock x:Name="tbCapName" Grid.Column="2" Margin="14,0,0,0" Foreground="Cyan" FontSize="14" FontFamily="Courier New" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
        <Button x:Name="btMin" Grid.Column="3" Content="&#x2013;" Width="40" Height="25" Padding="0" Margin="0,0,6,0" Style="{StaticResource PurpleBtn}" shell:WindowChrome.IsHitTestVisibleInChrome="True" ToolTip="Minimize"/>
        <Button x:Name="btMax" Grid.Column="4" Content="&#x25A1;" Width="40" Height="25" Padding="0" Margin="0,0,6,0" Style="{StaticResource PurpleBtn}" shell:WindowChrome.IsHitTestVisibleInChrome="True" ToolTip="Maximize / Restore"/>
        <Button x:Name="btExit" Grid.Column="5" Content="Exit" Width="60" Height="25" Padding="0" Margin="0,0,10,0" Style="{StaticResource PurpleBtn}" shell:WindowChrome.IsHitTestVisibleInChrome="True"/>
    </Grid>

    <!-- Menu bar: Analyze, Statistics, Telephony, Wireless and Tools are intentionally not implemented -->
    <Menu x:Name="menuMain" Grid.Row="1" IsMainMenu="True">
        <MenuItem Header="_File">
            <MenuItem x:Name="miOpen" Header="_Open..." InputGestureText="Ctrl+O"/>
            <MenuItem x:Name="miSave" Header="_Save" InputGestureText="Ctrl+S"/>
            <MenuItem x:Name="miSaveAs" Header="Save _As..." InputGestureText="Ctrl+Shift+S"/>
            <Separator/>
            <MenuItem x:Name="miClose" Header="_Close" InputGestureText="Ctrl+W"/>
            <Separator/>
            <MenuItem x:Name="miQuit" Header="_Quit" InputGestureText="Ctrl+Q"/>
        </MenuItem>
        <MenuItem Header="_Edit">
            <MenuItem x:Name="miCopy" Header="_Copy Packet Summary" InputGestureText="Ctrl+Shift+C"/>
            <Separator/>
            <MenuItem x:Name="miFind" Header="_Find Packet..." InputGestureText="Ctrl+F"/>
            <MenuItem x:Name="miFindNext" Header="Find _Next" InputGestureText="Ctrl+N"/>
            <MenuItem x:Name="miFindPrev" Header="Find Pre_vious" InputGestureText="Ctrl+B"/>
        </MenuItem>
        <MenuItem Header="_View">
            <MenuItem x:Name="miShowDetails" Header="Packet _Details" IsCheckable="True" IsChecked="True"/>
            <MenuItem x:Name="miShowBytes" Header="Packet _Bytes" IsCheckable="True" IsChecked="True"/>
            <Separator/>
            <MenuItem x:Name="miZoomIn" Header="Zoom _In" InputGestureText="Ctrl++"/>
            <MenuItem x:Name="miZoomOut" Header="Zoom _Out" InputGestureText="Ctrl+-"/>
            <MenuItem x:Name="miZoomReset" Header="_Normal Size" InputGestureText="Ctrl+0"/>
            <MenuItem x:Name="miResizeCols" Header="_Resize All Columns" InputGestureText="Ctrl+Shift+R"/>
            <Separator/>
            <MenuItem x:Name="miExpandAll" Header="_Expand All" InputGestureText="Ctrl+Right"/>
            <MenuItem x:Name="miCollapseAll" Header="Collapse A_ll" InputGestureText="Ctrl+Left"/>
            <Separator/>
            <MenuItem x:Name="miAutoScroll" Header="_Auto Scroll in Live Capture" IsCheckable="True" IsChecked="True"/>
            <MenuItem x:Name="miColorize" Header="Colorize _Packet List" IsCheckable="True" IsChecked="True"/>
        </MenuItem>
        <MenuItem Header="_Go">
            <MenuItem x:Name="miGoTo" Header="_Go to Packet..." InputGestureText="Ctrl+G"/>
            <Separator/>
            <MenuItem x:Name="miPrev" Header="_Previous Packet" InputGestureText="Ctrl+Up"/>
            <MenuItem x:Name="miNext" Header="_Next Packet" InputGestureText="Ctrl+Down"/>
            <MenuItem x:Name="miFirst" Header="_First Packet" InputGestureText="Ctrl+Home"/>
            <MenuItem x:Name="miLast" Header="_Last Packet" InputGestureText="Ctrl+End"/>
        </MenuItem>
        <MenuItem Header="_Capture">
            <MenuItem x:Name="miCapOptions" Header="_Options..." InputGestureText="Ctrl+K"/>
            <Separator/>
            <MenuItem x:Name="miCapStart" Header="_Start" InputGestureText="Ctrl+E"/>
            <MenuItem x:Name="miCapStop" Header="S_top" InputGestureText="Ctrl+E"/>
            <MenuItem x:Name="miCapRestart" Header="_Restart" InputGestureText="Ctrl+R"/>
        </MenuItem>
        <MenuItem Header="_Help">
            <MenuItem x:Name="miAbout" Header="_About PSShark"/>
        </MenuItem>
    </Menu>

    <!-- Main toolbar -->
    <Border Grid.Row="2" Background="#181735" BorderBrush="#2E2C6B" BorderThickness="0,1,0,1" Padding="4,3">
        <StackPanel Orientation="Horizontal">
            <Button x:Name="tbStart" Style="{StaticResource ToolBtn}" Content="&#xE768;" ToolTip="Start capturing packets (Ctrl+E)" Foreground="Lime"/>
            <Button x:Name="tbStop" Style="{StaticResource ToolBtn}" Content="&#xE71A;" ToolTip="Stop capturing packets (Ctrl+E)" Foreground="#FF4C70"/>
            <Button x:Name="tbRestart" Style="{StaticResource ToolBtn}" Content="&#xE72C;" ToolTip="Restart the current capture (Ctrl+R)"/>
            <Button x:Name="tbOptions" Style="{StaticResource ToolBtn}" Content="&#xE713;" ToolTip="Capture options (Ctrl+K)"/>
            <Rectangle Width="1" Margin="6,3" Fill="#2E2C6B"/>
            <Button x:Name="tbOpen" Style="{StaticResource ToolBtn}" Content="&#xE838;" ToolTip="Open a capture file (Ctrl+O)"/>
            <Button x:Name="tbSave" Style="{StaticResource ToolBtn}" Content="&#xE74E;" ToolTip="Save this capture file (Ctrl+S)"/>
            <Button x:Name="tbClose" Style="{StaticResource ToolBtn}" Content="&#xE711;" ToolTip="Close this capture file (Ctrl+W)"/>
            <Rectangle Width="1" Margin="6,3" Fill="#2E2C6B"/>
            <Button x:Name="tbFind" Style="{StaticResource ToolBtn}" Content="&#xE721;" ToolTip="Find a packet (Ctrl+F)"/>
            <Button x:Name="tbPrev" Style="{StaticResource ToolBtn}" Content="&#xE72B;" ToolTip="Previous packet (Ctrl+Up)"/>
            <Button x:Name="tbNext" Style="{StaticResource ToolBtn}" Content="&#xE72A;" ToolTip="Next packet (Ctrl+Down)"/>
            <Button x:Name="tbGoTo" Style="{StaticResource ToolBtn}" Content="&#xE7C0;" ToolTip="Go to packet (Ctrl+G)"/>
            <Button x:Name="tbFirst" Style="{StaticResource ToolBtn}" Content="&#xE74A;" ToolTip="Go to first packet (Ctrl+Home)"/>
            <Button x:Name="tbLast" Style="{StaticResource ToolBtn}" Content="&#xE74B;" ToolTip="Go to last packet (Ctrl+End)"/>
            <ToggleButton x:Name="tgAutoScroll" Style="{StaticResource ToolToggle}" Content="&#xE896;" ToolTip="Auto scroll in live capture" IsChecked="True"/>
            <ToggleButton x:Name="tgColorize" Style="{StaticResource ToolToggle}" Content="&#xE790;" ToolTip="Colorize packet list" IsChecked="True"/>
            <ToggleButton x:Name="tgBytes" Style="{StaticResource ToolToggle}" Content="0x" FontFamily="Consolas" FontSize="13" FontWeight="Bold" ToolTip="Show / hide the packet bytes pane (the decode tree then uses the full width)" IsChecked="True"/>
            <Rectangle Width="1" Margin="6,3" Fill="#2E2C6B"/>
            <Button x:Name="tbZoomIn" Style="{StaticResource ToolBtn}" Content="&#xE8A3;" ToolTip="Zoom in (Ctrl++)"/>
            <Button x:Name="tbZoomOut" Style="{StaticResource ToolBtn}" Content="&#xE71F;" ToolTip="Zoom out (Ctrl+-)"/>
            <Button x:Name="tbZoomReset" Style="{StaticResource ToolBtn}" Content="&#xE73F;" ToolTip="Normal size (Ctrl+0)"/>
            <Button x:Name="tbResizeCols" Style="{StaticResource ToolBtn}" Content="&#xE7EA;" ToolTip="Resize columns to fit contents"/>
        </StackPanel>
    </Border>

    <!-- Filter bar -->
    <Grid Grid.Row="3" Background="#181735" Margin="6,4">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <TextBlock Grid.Column="0" Text="&#xE71C;" FontFamily="Segoe MDL2 Assets" Foreground="Yellow" FontSize="14" VerticalAlignment="Center" Margin="4,0,8,0"/>
        <Grid Grid.Column="1">
            <TextBox x:Name="tbFilter" FontFamily="Consolas" FontSize="13" VerticalContentAlignment="Center" Height="26"/>
            <TextBlock IsHitTestVisible="False" Text="Apply a display filter ... e.g. tcp, ip.addr == 10.0.0.1, udp.port == 53, dns   (Ctrl+/)" Foreground="#6C6FA8" FontFamily="Consolas" FontSize="13" VerticalAlignment="Center" Margin="8,0,0,0">
                <TextBlock.Style>
                    <Style TargetType="TextBlock">
                        <Setter Property="Visibility" Value="Collapsed"/>
                        <Style.Triggers>
                            <DataTrigger Binding="{Binding Text, ElementName=tbFilter}" Value="">
                                <Setter Property="Visibility" Value="Visible"/>
                            </DataTrigger>
                        </Style.Triggers>
                    </Style>
                </TextBlock.Style>
            </TextBlock>
        </Grid>
        <Button x:Name="btApply" Grid.Column="2" Content="&#xE72A;" FontFamily="Segoe MDL2 Assets" Width="34" Height="26" Padding="0" Margin="6,0,0,0" Style="{StaticResource PurpleBtn}" ToolTip="Apply display filter (Enter)"/>
        <Button x:Name="btClear" Grid.Column="3" Content="&#xE711;" FontFamily="Segoe MDL2 Assets" Width="34" Height="26" Padding="0" Margin="6,0,0,0" Style="{StaticResource PurpleBtn}" ToolTip="Clear display filter"/>
    </Grid>

    <!-- Packet list / details / bytes -->
    <Grid x:Name="gMain" Grid.Row="4">
        <Grid.RowDefinitions>
            <RowDefinition Height="3*" MinHeight="80"/>
            <RowDefinition Height="5"/>
            <RowDefinition x:Name="rowBottom" Height="2*" MinHeight="60"/>
        </Grid.RowDefinitions>

        <DataGrid x:Name="dgPackets" Grid.Row="0" AutoGenerateColumns="False" IsReadOnly="True" SelectionMode="Single" SelectionUnit="FullRow"
                  HeadersVisibility="Column" GridLinesVisibility="None" CanUserAddRows="False" CanUserDeleteRows="False" CanUserResizeRows="False"
                  EnableRowVirtualization="True" VirtualizingPanel.IsVirtualizing="True" VirtualizingPanel.VirtualizationMode="Recycling"
                  RowHeight="20" FontFamily="Consolas" FontSize="13" Background="#181735" BorderThickness="0"
                  HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto" AllowDrop="True"
                  RowStyle="{StaticResource RowColor}">
            <DataGrid.Columns>
                <DataGridTextColumn Header="No." Binding="{Binding No}" Width="70" ElementStyle="{StaticResource CellTextR}"/>
                <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="120" ElementStyle="{StaticResource CellText}"/>
                <DataGridTextColumn Header="Source" Binding="{Binding Source}" Width="190" ElementStyle="{StaticResource CellText}"/>
                <DataGridTextColumn Header="Destination" Binding="{Binding Destination}" Width="190" ElementStyle="{StaticResource CellText}"/>
                <DataGridTextColumn Header="Protocol" Binding="{Binding Protocol}" Width="80" ElementStyle="{StaticResource CellText}"/>
                <DataGridTextColumn Header="Length" Binding="{Binding Length}" Width="70" ElementStyle="{StaticResource CellTextR}"/>
                <DataGridTextColumn Header="Info" Binding="{Binding Info}" Width="*" MinWidth="300" ElementStyle="{StaticResource CellText}"/>
            </DataGrid.Columns>
        </DataGrid>

        <GridSplitter Grid.Row="1" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Background="#2E2C6B" ResizeDirection="Rows" ResizeBehavior="PreviousAndNext"/>

        <Grid x:Name="gBottom" Grid.Row="2">
            <Grid.ColumnDefinitions>
                <ColumnDefinition x:Name="colDetails" Width="*" MinWidth="120"/>
                <ColumnDefinition x:Name="colSplit" Width="5"/>
                <ColumnDefinition x:Name="colBytes" Width="*" MinWidth="120"/>
            </Grid.ColumnDefinitions>

            <TreeView x:Name="tvDetail" Grid.Column="0" Background="#181735" Foreground="#E8E8FF" BorderThickness="0" FontFamily="Consolas" FontSize="13"
                      ScrollViewer.HorizontalScrollBarVisibility="Auto" ScrollViewer.VerticalScrollBarVisibility="Auto">
                <TreeView.ContextMenu><ContextMenu x:Name="cmDetail"/></TreeView.ContextMenu>
                <TreeView.Resources>
                    <SolidColorBrush x:Key="{x:Static SystemColors.HighlightBrushKey}" Color="#FFF200"/>
                    <SolidColorBrush x:Key="{x:Static SystemColors.HighlightTextBrushKey}" Color="Black"/>
                    <SolidColorBrush x:Key="{x:Static SystemColors.InactiveSelectionHighlightBrushKey}" Color="#C9BE00"/>
                    <SolidColorBrush x:Key="{x:Static SystemColors.InactiveSelectionHighlightTextBrushKey}" Color="Black"/>
                </TreeView.Resources>
                <TreeView.ItemContainerStyle>
                    <Style TargetType="TreeViewItem">
                        <Setter Property="IsExpanded" Value="{Binding Expanded, Mode=TwoWay}"/>
                        <Setter Property="Foreground" Value="#E8E8FF"/>
                    </Style>
                </TreeView.ItemContainerStyle>
                <TreeView.ItemTemplate>
                    <HierarchicalDataTemplate ItemsSource="{Binding Children}">
                        <TextBlock Text="{Binding Text}"/>
                    </HierarchicalDataTemplate>
                </TreeView.ItemTemplate>
            </TreeView>

            <GridSplitter x:Name="splitBytes" Grid.Column="1" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Background="#2E2C6B" ResizeDirection="Columns" ResizeBehavior="PreviousAndNext"/>

            <RichTextBox x:Name="rtbHex" Grid.Column="2" IsReadOnly="True" Background="#181735" Foreground="#E8E8FF" BorderThickness="0" FontFamily="Consolas" FontSize="13"
                         HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto" IsDocumentEnabled="False" Padding="4,2"/>
        </Grid>
    </Grid>

    <!-- Status bar -->
    <Border Grid.Row="5" Background="#0F0F4D" BorderBrush="#2E2C6B" BorderThickness="0,1,0,0">
        <Grid Margin="8,0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <Ellipse x:Name="dotState" Grid.Column="0" Width="11" Height="11" Fill="Yellow" VerticalAlignment="Center" Margin="0,0,8,0"/>
            <TextBlock x:Name="tbStatusMsg" Grid.Column="1" Foreground="Bisque" FontFamily="Consolas" VerticalAlignment="Center" TextTrimming="CharacterEllipsis" Margin="14,0,8,0"/>
            <ProgressBar x:Name="pbWork" Grid.Column="1" Width="160" Height="10" HorizontalAlignment="Right" VerticalAlignment="Center" Margin="0,0,10,0" Minimum="0" Maximum="100" Visibility="Collapsed" Background="#181735" Foreground="#FF4C70" BorderBrush="#552284"/>
            <TextBlock x:Name="tbCounts" Grid.Column="2" Foreground="Honeydew" FontFamily="Consolas" VerticalAlignment="Center" Margin="10,0"/>
            <TextBlock Grid.Column="3" Text="Profile: Default" Foreground="Cyan" FontFamily="Consolas" VerticalAlignment="Center" Margin="10,0,0,0"/>
        </Grid>
    </Border>
</Grid>
</Border>
'@

$script:windowXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    xmlns:shell="clr-namespace:System.Windows.Shell;assembly=PresentationFramework"
    Title="PSShark" Width="1280" Height="800" MinWidth="760" MinHeight="460"
    WindowStyle="None" ResizeMode="CanResize" WindowStartupLocation="CenterScreen"
    Background="#181735" Foreground="#E8E8FF" FontFamily="Segoe UI" FontSize="13"
    UseLayoutRounding="True" SnapsToDevicePixels="True" AllowDrop="True">
@@STYLES@@
@@BODY@@
</Window>
'@

# Small dialog shell (custom title bar, resizable, scrolls when the body does not fit)
$script:dialogXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    xmlns:shell="clr-namespace:System.Windows.Shell;assembly=PresentationFramework"
    Title="@@TITLE@@" Width="@@W@@" Height="@@H@@" MinWidth="320" MinHeight="160"
    WindowStyle="None" ResizeMode="CanResize" WindowStartupLocation="CenterOwner" ShowInTaskbar="False"
    Background="#181735" Foreground="#E8E8FF" FontFamily="Segoe UI" FontSize="13" UseLayoutRounding="True">
@@STYLES@@
<shell:WindowChrome.WindowChrome>
    <shell:WindowChrome CaptionHeight="34" ResizeBorderThickness="6" GlassFrameThickness="0" CornerRadius="0" UseAeroCaptionButtons="False"/>
</shell:WindowChrome.WindowChrome>
<Border Background="#181735" BorderBrush="#552284" BorderThickness="1">
    <Grid>
        <Grid.RowDefinitions><RowDefinition Height="34"/><RowDefinition Height="*"/></Grid.RowDefinitions>
        <Grid Grid.Row="0" Background="#0F0F4D">
            <TextBlock Text="@@TITLE@@" Foreground="Yellow" FontSize="16" FontWeight="Bold" FontFamily="Courier New" VerticalAlignment="Center" Margin="14,0,0,0"/>
            <Button x:Name="btnDlgClose" Content="Close" Width="60" Height="25" Padding="0" Margin="0,0,10,0" HorizontalAlignment="Right" Style="{StaticResource PurpleBtn}" shell:WindowChrome.IsHitTestVisibleInChrome="True"/>
        </Grid>
        <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto">
            <Grid x:Name="host" Margin="16">
@@BODY@@
            </Grid>
        </ScrollViewer>
    </Grid>
</Border>
</Window>
'@

############################################################################
# Application state
############################################################################
$script:pool        = $null
$script:workers     = New-Object System.Collections.ArrayList
$script:store       = New-Object PSShark.PacketStore
$script:rawQ        = New-Object 'System.Collections.Concurrent.ConcurrentQueue[PSShark.RawPacket]'
$script:uiQ         = New-Object 'System.Collections.Concurrent.ConcurrentQueue[PSShark.Packet]'
$script:dis         = New-Object PSShark.Dissector
$script:capState    = $null      # live capture worker state
$script:readState   = $null      # file reader worker state
$script:parseState  = $null      # dissector worker state
$script:writeState  = $null      # pcap writer worker state
$script:writeTarget = $null
$script:writeIsText = $false
$script:writeCount = 0
$script:notice = $null      # short message shown in the status bar for a few seconds
$script:noticeUntil = [DateTime]::MinValue
$script:capEndDone  = $true
$script:pendingRestart = $false
$script:filePath    = $null
$script:dirty       = $false     # live-captured packets not yet saved
$script:capFiltered = $false    # did the current/last live capture use a capture filter?
$script:iface       = @{ Name = $null; Promisc = $true; UseFilter = $false; Filter = '' }
$script:zoom        = 13
$script:defaultZoom = 13
$script:treeNodes   = $null
$script:lastFind    = ''
$script:lastWorkerError = $null
$script:inTick      = $false
$script:appIcon     = $null
$script:isAdmin     = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:adapters    = [hashtable]::Synchronized(@{ Ready = $false; List = @(); Error = $null })
$script:hlBrush     = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString('#FFF200'))
$script:hlBrush.Freeze()
$script:scriptPath  = $PSCommandPath
$ui = @{}
$script:filterRed   = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString('#FF5C5C'))
$script:filterGreen = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString('#5CFF7A'))
$script:filterBorderDefault = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString('#552284'))

############################################################################
# Worker helpers (background runspaces keep the UI thread free)
############################################################################
function Start-Worker {
    param([scriptblock]$Script, [object[]]$ArgumentList)
    $ps = [powershell]::Create()
    $ps.RunspacePool = $script:pool
    [void]$ps.AddScript($Script.ToString())
    foreach ($a in $ArgumentList) { [void]$ps.AddArgument($a) }
    $w = [pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() }
    [void]$script:workers.Add($w)
    return $w
}

function Clear-Workers {
    for ($i = $script:workers.Count - 1; $i -ge 0; $i--) {
        $w = $script:workers[$i]
        if ($w.Handle.IsCompleted) {
            try { [void]$w.PS.EndInvoke($w.Handle) } catch { $script:lastWorkerError = $_.Exception.Message }
            if ($w.PS.Streams.Error.Count -gt 0) { $script:lastWorkerError = $w.PS.Streams.Error[0].ToString() }
            $w.PS.Dispose()
            $script:workers.RemoveAt($i)
        }
    }
}

$script:captureWorker = {
    param($ifName, $promisc, $rawQ, $st, $sess)
    try {
        $st.Status = 'Configuring capture session...'
        $old = Get-NetEventSession -Name $sess -ErrorAction SilentlyContinue
        if ($old) {
            try { Stop-NetEventSession -Name $sess -ErrorAction SilentlyContinue } catch {}
            try { Remove-NetEventSession -Name $sess -ErrorAction SilentlyContinue } catch {}
        }
        New-NetEventSession -Name $sess -CaptureMode RealtimeLocal -ErrorAction Stop | Out-Null
        Add-NetEventPacketCaptureProvider -SessionName $sess -TruncationLength 65535 -ErrorAction Stop | Out-Null
        Add-NetEventNetworkAdapter -Name $ifName -PromiscuousMode $promisc -ErrorAction Stop | Out-Null
        Start-NetEventSession -Name $sess -ErrorAction Stop
        $st.Status = 'Capturing'
        if ($st.Cancel) { return }
        $err = [PSShark.EtwLive]::Run($sess, $rawQ, $st)
        if ($err) { $st.Error = $err }
    }
    catch { $st.Error = $_.Exception.Message }
    finally {
        try { Stop-NetEventSession -Name $sess -ErrorAction SilentlyContinue } catch {}
        try { Remove-NetEventSession -Name $sess -ErrorAction SilentlyContinue } catch {}
        try { Remove-NetEventNetworkAdapter -Name $ifName -ErrorAction SilentlyContinue } catch {}
        $st.Done = $true
    }
}

$script:adapterWorker = {
    param($box)
    try {
        $ips = @{}
        try { Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object { if (-not $ips.ContainsKey($_.InterfaceAlias)) { $ips[$_.InterfaceAlias] = "$($_.IPAddress)" } } } catch {}
        $list = @(Get-NetAdapter -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Name = "$($_.Name)"; Description = "$($_.InterfaceDescription)"; Status = "$($_.Status)"; Speed = "$($_.LinkSpeed)"; IP = "$($ips[$_.Name])"; Guid = "$($_.InterfaceGuid)" }
        })
        $box.List = $list
    }
    catch { $box.Error = $_.Exception.Message }
    finally { $box.Ready = $true }
}

############################################################################
# Capture control
############################################################################
function Test-Busy {
    $capActive = ($null -ne $script:capState) -and (-not $script:capState.Done)
    $loading   = ($null -ne $script:readState) -and (-not ($script:readState.Done -and $script:parseState.Done))
    return ($capActive -or $loading)
}

function Confirm-Discard {
    param([string]$Action = 'continue')
    if (-not $script:dirty) { return $true }
    $r = [Windows.MessageBox]::Show($window, "The captured packets have not been saved.`nDiscard them and ${Action}?", 'PSShark', 'YesNo', 'Warning')
    return ($r -eq 'Yes')
}

function Reset-Capture {
    foreach ($st in @($script:readState, $script:parseState)) { if ($null -ne $st) { $st.Cancel = $true } }
    $script:rawQ  = New-Object 'System.Collections.Concurrent.ConcurrentQueue[PSShark.RawPacket]'
    $script:uiQ   = New-Object 'System.Collections.Concurrent.ConcurrentQueue[PSShark.Packet]'
    $script:dis   = New-Object PSShark.Dissector
    $script:readState = $null
    $script:parseState = $null
    $script:store.Reset()
    $script:dirty = $false
    $script:filePath = $null
    $ui.dgPackets.SelectedItem = $null
    $ui.tvDetail.ItemsSource = $null
    Set-Hex $null 0 0
}

function Start-ParseWorker {
    param($Producer, $Keep = $null)
    $script:parseState = New-Object PSShark.SharedState
    [void](Start-Worker { param($r, $u, $d, $s, $p, $k) [PSShark.ParseLoop]::Run($r, $u, $d, $s, $p, $k) } @($script:rawQ, $script:uiQ, $script:dis, $script:parseState, $Producer, $Keep))
}

function Open-CaptureFile {
    param([string]$Path)
    if (Test-Busy) { return }
    if (-not (Test-Path -LiteralPath $Path)) { [void][Windows.MessageBox]::Show($window, "File not found:`n$Path", 'PSShark', 'OK', 'Error'); return }
    if (-not (Confirm-Discard 'open the file')) { return }
    Reset-Capture
    $script:filePath = $Path
    $script:readState = New-Object PSShark.SharedState
    [void](Start-Worker { param($p, $q, $s) [PSShark.PcapIO]::Read($p, $q, $s) } @($Path, $script:rawQ, $script:readState))
    Start-ParseWorker $script:readState
    Update-Title
}

function Start-Capture {
    param([switch]$NoConfirm)
    if (Test-Busy) { return }
    if (-not (Get-Module -ListAvailable -Name NetEventPacketCapture)) {
        [void][Windows.MessageBox]::Show($window, 'The NetEventPacketCapture PowerShell module is not available on this system.', 'PSShark', 'OK', 'Error'); return
    }
    if (-not $script:isAdmin) {
        $r = [Windows.MessageBox]::Show($window, "Capturing packets requires Administrator rights.`nRestart PSShark as Administrator?", 'PSShark', 'YesNo', 'Question')
        if ($r -eq 'Yes') { Restart-Elevated }
        return
    }
    if (-not $script:iface.Name) { if (-not (Show-CaptureOptions)) { return } }
    if (-not $NoConfirm) { if (-not (Confirm-Discard 'start a new capture')) { return } }
    Reset-Capture
    $script:capState = New-Object PSShark.SharedState
    $script:capEndDone = $false
    $ad = @($script:adapters.List) | Where-Object { $_.Name -eq $script:iface.Name } | Select-Object -First 1
    [PSShark.EtwLive]::IfName = if ($null -ne $ad -and $ad.Guid) { '\Device\NPF_' + $ad.Guid } else { $script:iface.Name }
    [PSShark.EtwLive]::IfDesc = $script:iface.Name
    $sess = 'PSShark'
    [void](Start-Worker $script:captureWorker @($script:iface.Name, [bool]$script:iface.Promisc, $script:rawQ, $script:capState, $sess))
    $keep = $null
    if ($script:iface.UseFilter -and $script:iface.Filter) {
        try { $keep = [PSShark.PacketFilter]::Compile($script:iface.Filter) } catch { $keep = $null }
    }
    $script:capFiltered = ($null -ne $keep)
    Start-ParseWorker $script:capState $keep
    Update-Title
}

function Stop-Capture {
    if ($null -ne $script:capState -and -not $script:capState.Done) {
        $script:capState.Cancel = $true
        [PSShark.EtwLive]::Close()
    }
    elseif ($null -ne $script:readState -and -not $script:readState.Done) {
        $script:readState.Cancel = $true
    }
}

function Restart-Capture {
    if ($null -ne $script:capState -and -not $script:capState.Done) {
        if (-not (Confirm-Discard 'restart the capture')) { return }
        $script:dirty = $false
        $script:pendingRestart = $true
        Stop-Capture
    }
    else { Start-Capture }
}

function Close-Capture {
    if (Test-Busy) { return }
    if (-not (Confirm-Discard 'close the capture')) { return }
    Reset-Capture
    Update-Title
}

function Restart-Elevated {
    try {
        $exe = (Get-Process -Id $PID).Path
        $a = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $script:scriptPath + '"'))
        $open = if ($script:filePath) { $script:filePath } else { $OpenFile }
        if ($open) { $a += @('-OpenFile', ('"' + $open + '"')) }
        Start-Process -FilePath $exe -ArgumentList $a -Verb RunAs -ErrorAction Stop
        $script:dirty = $false
        $window.Close()
    }
    catch { [void][Windows.MessageBox]::Show($window, "Could not restart as Administrator:`n$($_.Exception.Message)", 'PSShark', 'OK', 'Error') }
}

############################################################################
# Saving
############################################################################
function Save-CaptureAs {
    if ($script:store.All.Count -eq 0 -or ($null -ne $script:writeState -and -not $script:writeState.Done)) { return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'Wireshark/tcpdump - pcap (*.pcap)|*.pcap|Text - pktmon etl2txt style, rows in the table (*.txt)|*.txt|All files (*.*)|*.*'
    $dlg.AddExtension = $false
    $base = if ($script:filePath) { [IO.Path]::GetFileNameWithoutExtension($script:filePath) } else { 'capture_' + (Get-Date -Format 'yyyyMMdd_HHmmss') }
    $dlg.FileName = $base
    if ($dlg.ShowDialog($window) -ne $true) { return }
    $path = $dlg.FileName
    $ext = [IO.Path]::GetExtension($path).ToLower()
    if (-not $ext) { $ext = if ($dlg.FilterIndex -eq 2) { '.txt' } else { '.pcap' }; $path += $ext }
    Save-CaptureTo $path -Text:($ext -eq '.txt')
}

function Save-CaptureTo {
    param([string]$Path, [switch]$Text)
    $snap = New-Object 'System.Collections.Generic.List[PSShark.Packet]'
    if ($Text) { $snap = $script:store.Displayed() }       # the rows in the table
    else { $snap.AddRange($script:store.All) }             # a capture file always gets every packet
    $script:writeState = New-Object PSShark.SharedState
    $script:writeTarget = $Path
    $script:writeIsText = [bool]$Text
    $script:writeCount = $snap.Count
    if ($Text) { [void](Start-Worker { param($p, $l, $s) [PSShark.PktmonText]::Write($p, $l, $s) } @($Path, $snap, $script:writeState)) }
    else { [void](Start-Worker { param($p, $l, $s) [PSShark.PcapIO]::Write($p, $l, $s) } @($Path, $snap, $script:writeState)) }
}

function Save-Capture {
    if ($script:filePath -and $script:filePath -match '\.pcap$' -and -not $script:dirty) { Save-CaptureTo $script:filePath }
    else { Save-CaptureAs }
}

function Open-CaptureDialog {
    if (Test-Busy) { return }
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Filter = 'Capture files (*.pcap;*.pcapng;*.cap)|*.pcap;*.pcapng;*.cap|All files (*.*)|*.*'
    if ($dlg.ShowDialog($window) -eq $true) { Open-CaptureFile $dlg.FileName }
}

############################################################################
# Packet list / detail / bytes
############################################################################
function Set-Hex {
    param($Data, [int]$Start, [int]$Length)
    $doc = New-Object Windows.Documents.FlowDocument
    $doc.PageWidth = 1400
    $para = New-Object Windows.Documents.Paragraph
    $para.Margin = New-Object Windows.Thickness(0)
    if ($null -ne $Data) {
        foreach ($seg in [PSShark.HexDump]::Build($Data, $Start, $Length)) {
            $parts = $seg.Text.Split("`n")
            for ($i = 0; $i -lt $parts.Length; $i++) {
                if ($i -gt 0) { [void]$para.Inlines.Add((New-Object Windows.Documents.LineBreak)) }
                if ($parts[$i].Length -eq 0) { continue }
                $run = New-Object Windows.Documents.Run($parts[$i])
                if ($seg.Hl) { $run.Background = $script:hlBrush; $run.Foreground = [Windows.Media.Brushes]::Black }
                [void]$para.Inlines.Add($run)
            }
        }
    }
    [void]$doc.Blocks.Add($para)
    $ui.rtbHex.Document = $doc
}

# Addresses on a packet-details line -> menu entries ("Copy source MAC" ...). A line such as
# "Ethernet II, Src: a, Dst: b" gives both; "Source: a" / "Sender IP address: a" gives one.
function Find-Address {
    param([string]$Text)
    $m = [regex]::Match($Text, '(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}')
    if ($m.Success) { return @{ Kind = 'MAC'; Value = $m.Value } }
    $m = [regex]::Match($Text, '(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
    if ($m.Success) { $ip = $null; if ([Net.IPAddress]::TryParse($m.Value, [ref]$ip)) { return @{ Kind = 'IP'; Value = $m.Value } } }
    foreach ($tok in ($Text -split '[\s,()]+')) {
        $ip = $null
        if ($tok -match ':' -and [Net.IPAddress]::TryParse($tok, [ref]$ip) -and $ip.AddressFamily -eq 'InterNetworkV6') { return @{ Kind = 'IP'; Value = $tok } }
    }
    return $null
}

function Get-AddressActions {
    param([string]$Text)
    $list = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrEmpty($Text)) { return }
    $t = $Text.Trim()
    $pairs = @()      # @(role, text)
    $m = [regex]::Match($t, 'Src:\s*(?<s>.*?),\s*Dst:\s*(?<d>.*)$')
    if ($m.Success) { $pairs += , @('source', $m.Groups['s'].Value); $pairs += , @('destination', $m.Groups['d'].Value) }
    else {
        $m = [regex]::Match($t, '^(?<r>Source|Destination)(?: Address)?:\s*(?<v>.*)$')
        if ($m.Success) { $pairs += , @($m.Groups['r'].Value.ToLower(), $m.Groups['v'].Value) }
        else {
            $m = [regex]::Match($t, '^(?<r>Sender|Target) (?:MAC|IP) address:\s*(?<v>.*)$')
            if ($m.Success) { $pairs += , @($(if ($m.Groups['r'].Value -eq 'Sender') { 'source' } else { 'destination' }), $m.Groups['v'].Value) }
        }
    }
    foreach ($pr in $pairs) {
        $a = Find-Address $pr[1]
        if ($null -ne $a) { [void]$list.Add(@{ Label = "Copy $($pr[0]) $($a.Kind)"; Value = $a.Value }) }
    }
    return $list.ToArray()
}

function Find-TreeItemAt {
    param($Source)
    $o = $Source
    while ($null -ne $o -and $o -isnot [Windows.Controls.TreeViewItem]) {
        if ($o -is [Windows.Media.Visual] -or $o -is [Windows.Media.Media3D.Visual3D]) { $o = [Windows.Media.VisualTreeHelper]::GetParent($o) }
        else { $o = [Windows.LogicalTreeHelper]::GetParent($o) }
    }
    return $o
}

# Fills the details-pane context menu for one line; returns how many entries it has.
function Set-DetailMenu {
    param([string]$Text)
    $ui.cmDetail.Items.Clear()
    foreach ($act in (Get-AddressActions $Text)) {
        $mi = New-Object Windows.Controls.MenuItem
        $mi.Header = $act.Label
        $mi.Tag = $act.Value
        $mi.ToolTip = $act.Value
        $mi.Add_Click({ param($s, $e) try { [Windows.Clipboard]::SetText([string]$s.Tag) } catch { $ui.tbStatusMsg.Text = 'Could not copy to the clipboard: ' + $_.Exception.Message } })
        [void]$ui.cmDetail.Items.Add($mi)
    }
    return $ui.cmDetail.Items.Count
}

function Show-Packet {
    $p = $ui.dgPackets.SelectedItem
    if ($null -eq $p) { $ui.tvDetail.ItemsSource = $null; Set-Hex $null 0 0; return }
    $script:treeNodes = [PSShark.Dissector]::BuildTree($p)
    for ($i = 1; $i -lt $script:treeNodes.Count; $i++) { $script:treeNodes[$i].Expanded = $true }   # show each protocol layer (Frame stays collapsed)
    $ui.tvDetail.ItemsSource = $script:treeNodes
    Set-Hex $p.Data 0 0
}

function Select-PacketIndex {
    param([int]$Index)
    $n = $script:store.Count
    if ($n -eq 0) { return }
    if ($Index -lt 0) { $Index = 0 }
    if ($Index -ge $n) { $Index = $n - 1 }
    $ui.dgPackets.SelectedIndex = $Index
    $ui.dgPackets.ScrollIntoView($ui.dgPackets.SelectedItem)
}

# Filter syntax feedback: text turns red when the expression is wrong, green when it is valid.
function Set-FilterColor {
    param($TextBox)
    $t = $TextBox.Text.Trim()
    if (-not $t) {
        $TextBox.Foreground = [Windows.Media.Brushes]::White
        $TextBox.BorderBrush = $script:filterBorderDefault
        $TextBox.ToolTip = $null
        return
    }
    $err = [PSShark.PacketFilter]::Check($t)
    if ($err) {
        $TextBox.Foreground = $script:filterRed
        $TextBox.BorderBrush = $script:filterRed
        $TextBox.ToolTip = $err
    }
    else {
        $TextBox.Foreground = $script:filterGreen
        $TextBox.BorderBrush = $script:filterGreen
        $TextBox.ToolTip = 'Filter syntax is valid'
    }
}

function Invoke-DisplayFilter {
    $err = [PSShark.PacketFilter]::Check($ui.tbFilter.Text)
    if ($err) {
        [void][Windows.MessageBox]::Show($window, "The display filter is not valid:`n`n$err`n`nFilter: $($ui.tbFilter.Text)", 'PSShark - Invalid display filter', 'OK', 'Warning')
        [void]$ui.tbFilter.Focus()
        return
    }
    $script:store.Filter = [PSShark.PacketFilter]::Compile($ui.tbFilter.Text)
    $sel = $ui.dgPackets.SelectedItem
    $script:store.Refilter()
    if ($null -ne $sel) {
        $idx = $script:store.IndexOf($sel)
        if ($idx -ge 0) { Select-PacketIndex $idx }
    }
    Update-Title
}

function Find-Packet {
    param([bool]$Forward = $true)
    if ([string]::IsNullOrEmpty($script:lastFind)) { Show-FindDialog; return }
    $i = $script:store.Find($ui.dgPackets.SelectedIndex, $script:lastFind, $Forward)
    if ($i -ge 0) { Select-PacketIndex $i }
    else { $ui.tbStatusMsg.Text = "No packet contains '$($script:lastFind)'." }
}

function Set-Zoom {
    param([int]$Size)
    if ($Size -lt 8) { $Size = 8 }
    if ($Size -gt 30) { $Size = 30 }
    $script:zoom = $Size
    $ui.dgPackets.FontSize = $Size
    $ui.dgPackets.RowHeight = $Size + 7
    $ui.tvDetail.FontSize = $Size
    $ui.rtbHex.FontSize = $Size
}

function Set-TreeExpanded {
    param([bool]$Expanded)
    if ($null -eq $script:treeNodes) { return }
    [PSShark.TreeNode]::SetAll($script:treeNodes, $Expanded)
    $ui.tvDetail.ItemsSource = $null
    $ui.tvDetail.ItemsSource = $script:treeNodes
}

function Update-Panes {
    $d = [bool]$ui.miShowDetails.IsChecked
    $b = [bool]$ui.miShowBytes.IsChecked
    $star = { param($n) New-Object Windows.GridLength($n, [Windows.GridUnitType]::Star) }
    if (-not $d -and -not $b) {
        $ui.gBottom.Visibility = 'Collapsed'
        $ui.rowBottom.MinHeight = 0
        $ui.rowBottom.Height = New-Object Windows.GridLength(0)
    }
    else {
        $ui.gBottom.Visibility = 'Visible'
        $ui.rowBottom.MinHeight = 60
        $ui.rowBottom.Height = & $star 2
    }
    $ui.tvDetail.Visibility = if ($d) { 'Visible' } else { 'Collapsed' }
    $ui.rtbHex.Visibility = if ($b) { 'Visible' } else { 'Collapsed' }
    $ui.splitBytes.Visibility = if ($d -and $b) { 'Visible' } else { 'Collapsed' }
    $ui.colDetails.MinWidth = if ($d) { 120 } else { 0 }
    $ui.colBytes.MinWidth = if ($b) { 120 } else { 0 }
    $ui.colDetails.Width = if ($d) { & $star 1 } else { New-Object Windows.GridLength(0) }
    $ui.colBytes.Width = if ($b) { & $star 1 } else { New-Object Windows.GridLength(0) }
    $ui.colSplit.Width = if ($d -and $b) { New-Object Windows.GridLength(5) } else { New-Object Windows.GridLength(0) }
}

function Set-Colorize {
    param([bool]$On)
    $ui.dgPackets.RowStyle = if ($On) { $window.FindResource('RowColor') } else { $window.FindResource('RowPlain') }
    $ui.miColorize.IsChecked = $On
    $ui.tgColorize.IsChecked = $On
}

function Set-AutoScroll {
    param([bool]$On)
    $ui.miAutoScroll.IsChecked = $On
    $ui.tgAutoScroll.IsChecked = $On
}

############################################################################
# Title / status / enable state
############################################################################
function Update-Title {
    $capActive = ($null -ne $script:capState) -and (-not $script:capState.Done)
    $name = ''
    $mode = if ($script:capFiltered -or $null -ne $script:store.Filter) { ' (filtered)' } else { ' (unfiltered)' }   # capture filter or display filter
    if ($capActive) { $name = '*' + $script:iface.Name + $mode }
    elseif ($script:filePath) { $name = [IO.Path]::GetFileName($script:filePath) }
    elseif ($script:store.All.Count -gt 0 -and $script:iface.Name) { $name = '*' + $script:iface.Name + $mode }
    $ui.tbCapName.Text = $name
    $window.Title = if ($name) { "PSShark - $name" } else { 'PSShark' }
}

function Update-Controls {
    $capActive = ($null -ne $script:capState) -and (-not $script:capState.Done)
    $capRunning = $capActive -and (-not $script:capState.Cancel)
    $loading = ($null -ne $script:readState) -and (-not $script:readState.Done)
    $saving = ($null -ne $script:writeState) -and (-not $script:writeState.Done)
    $busy = Test-Busy
    $has = $script:store.All.Count -gt 0
    $canStart = -not $busy
    $canStop = $capRunning -or $loading
    $canRestart = ($capRunning -or ((-not $busy) -and [bool]$script:iface.Name))
    $canSave = $has -and (-not $saving) -and (-not $busy)
    $canClose = (-not $busy) -and ($has -or [bool]$script:filePath)
    foreach ($n in 'miCapStart', 'tbStart') { $ui[$n].IsEnabled = $canStart }
    foreach ($n in 'miCapStop', 'tbStop') { $ui[$n].IsEnabled = $canStop }
    foreach ($n in 'miCapRestart', 'tbRestart') { $ui[$n].IsEnabled = $canRestart }
    foreach ($n in 'miCapOptions', 'tbOptions') { $ui[$n].IsEnabled = -not $busy }
    foreach ($n in 'miOpen', 'tbOpen') { $ui[$n].IsEnabled = -not $busy }
    foreach ($n in 'miSave', 'miSaveAs', 'tbSave') { $ui[$n].IsEnabled = $canSave }
    foreach ($n in 'miClose', 'tbClose') { $ui[$n].IsEnabled = $canClose }
    $shown = $script:store.Count -gt 0
    foreach ($n in 'miFind', 'miFindNext', 'miFindPrev', 'miGoTo', 'miPrev', 'miNext', 'miFirst', 'miLast', 'miCopy', 'tbFind', 'tbGoTo', 'tbPrev', 'tbNext', 'tbFirst', 'tbLast') { $ui[$n].IsEnabled = $shown }
}

function Get-InterfaceLabel {
    $n = $script:iface.Name
    if (-not $n) { return $null }
    $a = @($script:adapters.List) | Where-Object { $_.Name -eq $n } | Select-Object -First 1
    if ($null -ne $a -and $a.IP) { return "$n ($($a.IP))" }
    return $n
}

function Update-Status {
    $total = $script:store.All.Count
    $shown = $script:store.Count
    $pct = if ($total -gt 0) { '{0:N1}' -f (100.0 * $shown / $total) } else { '0.0' }
    $ui.tbCounts.Text = "Packets: $total  Displayed: $shown ($pct%)"
    $capActive = ($null -ne $script:capState) -and (-not $script:capState.Done)
    $loading = ($null -ne $script:readState) -and (-not $script:readState.Done)
    $saving = ($null -ne $script:writeState) -and (-not $script:writeState.Done)
    $ui.pbWork.Visibility = 'Collapsed'
    if ($saving) {
        $ui.dotState.Fill = [Windows.Media.Brushes]::Orange
        $ui.tbStatusMsg.Text = $(if ($script:writeIsText) { "Exporting $($script:writeTarget) ..." } else { "Saving $($script:writeTarget) ..." })
        $ui.pbWork.Visibility = 'Visible'
        $ui.pbWork.Value = if ($script:writeState.Total -gt 0) { 100.0 * $script:writeState.Progress / $script:writeState.Total } else { 0 }
    }
    elseif ($script:notice -and (Get-Date) -lt $script:noticeUntil) {
        $ui.dotState.Fill = [Windows.Media.Brushes]::Lime
        $ui.tbStatusMsg.Text = $script:notice
    }
    elseif ($capActive) {
        $stopping = $script:capState.Cancel
        $ui.dotState.Fill = if ($stopping) { [Windows.Media.Brushes]::Orange } else { [Windows.Media.Brushes]::Lime }
        $msg = if ($stopping) { 'Stopping capture ...' } elseif ($script:capState.Status) { $script:capState.Status } else { 'Starting ...' }
        $flt = ''
        if ($script:iface.UseFilter -and $script:iface.Filter) { $flt = "  filter: $($script:iface.Filter)  (dropped: $($script:parseState.Progress))" }
        $rx = "  received: $($script:capState.Count)"
        $perr = ''
        if ($script:parseState -and $script:parseState.Error) { $perr = "  parse error: $($script:parseState.Error)" }
        elseif ($script:lastWorkerError) { $perr = "  worker error: $($script:lastWorkerError)" }
        $ui.tbStatusMsg.Text = "$msg  [$(Get-InterfaceLabel)]$rx$flt$perr"
    }
    elseif ($loading) {
        $ui.dotState.Fill = [Windows.Media.Brushes]::Yellow
        $ui.tbStatusMsg.Text = "Loading $($script:filePath) ..."
        $ui.pbWork.Visibility = 'Visible'
        $ui.pbWork.Value = if ($script:readState.Total -gt 0) { 100.0 * $script:readState.Progress / $script:readState.Total } else { 0 }
    }
    elseif ($script:filePath) {
        $ui.dotState.Fill = [Windows.Media.Brushes]::Lime
        $ui.tbStatusMsg.Text = $script:filePath
    }
    elseif ($total -gt 0) {
        $ui.dotState.Fill = [Windows.Media.Brushes]::Lime
        $ui.tbStatusMsg.Text = "Capture stopped ($($script:iface.Name)). Use File > Save As to keep it."
    }
    else {
        $ui.dotState.Fill = [Windows.Media.Brushes]::Yellow
        $ifText = if ($script:iface.Name) { Get-InterfaceLabel } else { '(none selected - use Capture > Options)' }
        $ui.tbStatusMsg.Text = if ($script:isAdmin) { "Ready to load or capture   Interface: $ifText" } else { "Ready to load a file. Capturing needs Administrator rights (you will be asked).   Interface: $ifText" }
    }
}

############################################################################
# Periodic UI tick: drain parsed packets, track worker completion
############################################################################
function Invoke-Tick {
    if ($script:inTick) { return }
    $script:inTick = $true
    try {
        $n = $script:store.Drain($script:uiQ, 30)
        $capActive = ($null -ne $script:capState) -and (-not $script:capState.Done)
        if ($n -gt 0) {
            if ($capActive) { $script:dirty = $true }
            if ($ui.miAutoScroll.IsChecked -and $capActive -and $script:store.Count -gt 0) {
                $ui.dgPackets.ScrollIntoView($script:store[$script:store.Count - 1])
            }
        }
        Clear-Workers

        if ($null -ne $script:capState -and $script:capState.Done -and -not $script:capEndDone) {
            $script:capEndDone = $true
            if ($script:capState.Error) {
                $hint = ''
                if ($script:capState.Error -match 'denied|privilege|Access') { $hint = "`n`nRun PSShark as Administrator." }
                [void][Windows.MessageBox]::Show($window, "Capture stopped: $($script:capState.Error)$hint", 'PSShark', 'OK', 'Warning')
            }
            if ($script:pendingRestart) { $script:pendingRestart = $false; Start-Capture -NoConfirm }
            Update-Title
        }
        if ($null -ne $script:readState -and $script:readState.Done -and $script:readState.Error) {
            $e = $script:readState.Error
            $script:readState.Error = $null
            [void][Windows.MessageBox]::Show($window, "Could not read the capture file:`n$e", 'PSShark', 'OK', 'Error')
        }
        if ($null -ne $script:writeState -and $script:writeState.Done) {
            $ws = $script:writeState
            $script:writeState = $null
            if ($ws.Error) { [void][Windows.MessageBox]::Show($window, "Could not save the file:`n$($ws.Error)", 'PSShark', 'OK', 'Error') }
            elseif ($script:writeIsText) {
                $of = if ($script:writeCount -lt $script:store.All.Count) { " (of $($script:store.All.Count); the display filter is applied)" } else { '' }
                $script:notice = "Exported $($script:writeCount) rows$of to $($script:writeTarget)"
                $script:noticeUntil = (Get-Date).AddSeconds(8)
            }
            else { $script:dirty = $false; $script:filePath = $script:writeTarget; Update-Title }
        }
        Update-Controls
        Update-Status
    }
    catch { $ui.tbStatusMsg.Text = 'Error: ' + $_.Exception.Message }
    finally { $script:inTick = $false }
}

############################################################################
# Dialogs
############################################################################
function New-Dialog {
    param([string]$Title, [double]$Width, [double]$Height, [string]$Body)
    $x = $script:dialogXaml.Replace('@@STYLES@@', $script:stylesXaml).Replace('@@TITLE@@', [Security.SecurityElement]::Escape($Title)).Replace('@@W@@', "$Width").Replace('@@H@@', "$Height").Replace('@@BODY@@', $Body)
    $dlg = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$x)))
    $dlg.Owner = $window
    if ($null -ne $script:appIcon) { $dlg.Icon = $script:appIcon }
    $dlg.FindName('btnDlgClose').Add_Click({ param($s, $e) [Windows.Window]::GetWindow($s).Close() })
    return $dlg
}

function Show-CaptureOptions {
    $body = @'
<Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
<TextBlock Grid.Row="0" Text="Select the network interface to capture from:" Foreground="Cyan" Margin="0,0,0,8"/>
<DataGrid x:Name="dgIf" Grid.Row="1" Height="200" AutoGenerateColumns="False" IsReadOnly="True" SelectionMode="Single" HeadersVisibility="Column"
          GridLinesVisibility="None" CanUserAddRows="False" Background="#181735" BorderBrush="#2E2C6B" RowHeight="24" RowStyle="{StaticResource RowPlain}"
          HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto">
    <DataGrid.Columns>
        <DataGridTextColumn Header="Interface" Binding="{Binding Name}" Width="170" ElementStyle="{StaticResource CellText}"/>
        <DataGridTextColumn Header="Description" Binding="{Binding Description}" Width="*" MinWidth="220" ElementStyle="{StaticResource CellText}"/>
        <DataGridTextColumn Header="IPv4" Binding="{Binding IP}" Width="120" ElementStyle="{StaticResource CellText}"/>
        <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="100" ElementStyle="{StaticResource CellText}"/>
        <DataGridTextColumn Header="Speed" Binding="{Binding Speed}" Width="100" ElementStyle="{StaticResource CellText}"/>
    </DataGrid.Columns>
</DataGrid>
<CheckBox x:Name="cbPromisc" Grid.Row="2" Content="Enable promiscuous mode on this interface" IsChecked="True" Margin="0,10,0,0"/>
<StackPanel Grid.Row="3" Margin="0,8,0,0">
    <CheckBox x:Name="cbFilter" Content="Only capture filtered packets (others are dropped and not stored)"/>
    <TextBox x:Name="tbCapFilter" Margin="20,6,0,0" FontFamily="Consolas" FontSize="13" IsEnabled="False" ToolTip="Same syntax as the display filter, e.g.  tcp &amp;&amp; ip.addr == 10.0.0.1   or   udp.port == 53   or   dns"/>
</StackPanel>
<Grid Grid.Row="4" Margin="0,12,0,0">
    <TextBlock x:Name="tbHint" Foreground="Yellow" VerticalAlignment="Center" TextWrapping="Wrap" Margin="0,0,180,0"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="btnOk" Content="Start" Style="{StaticResource PurpleBtn}" Width="80" Margin="0,0,8,0"/>
        <Button x:Name="btnCancel" Content="Cancel" Style="{StaticResource PurpleBtn}" Width="80"/>
    </StackPanel>
</Grid>
'@
    $dlg = New-Dialog 'Capture Options' 820 500 $body
    $dg = $dlg.FindName('dgIf')
    $cb = $dlg.FindName('cbPromisc')
    $hint = $dlg.FindName('tbHint')
    $cb.IsChecked = [bool]$script:iface.Promisc
    $cf = $dlg.FindName('cbFilter'); $tf = $dlg.FindName('tbCapFilter')
    $cf.IsChecked = [bool]$script:iface.UseFilter
    $tf.Text = if ($script:iface.Filter) { $script:iface.Filter } else { $ui.tbFilter.Text }
    $tf.IsEnabled = [bool]$cf.IsChecked
    $tf.Add_TextChanged({ param($s, $e) Set-FilterColor $s })
    Set-FilterColor $tf
    $cf.Add_Click({ param($s, $e) $w = [Windows.Window]::GetWindow($s); $w.FindName('tbCapFilter').IsEnabled = [bool]$s.IsChecked })
    $script:optDlg = @{ Grid = $dg; Hint = $hint; Filled = $false }
    $script:optFill = {
        if ($script:optDlg.Filled -or -not $script:adapters.Ready) { return }
        $script:optDlg.Filled = $true
        $list = @($script:adapters.List)
        $script:optDlg.Grid.ItemsSource = $list
        $sel = $null
        if ($script:iface.Name) { $sel = $list | Where-Object { $_.Name -eq $script:iface.Name } | Select-Object -First 1 }
        if ($null -eq $sel) { $sel = $list | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1 }
        if ($null -ne $sel) { $script:optDlg.Grid.SelectedItem = $sel }
        if ($script:adapters.Error) { $script:optDlg.Hint.Text = 'Could not list adapters: ' + $script:adapters.Error }
    }
    if ($script:adapters.Ready) { & $script:optFill } else { $hint.Text = 'Loading interfaces ...' }
    $script:optTimer = New-Object Windows.Threading.DispatcherTimer
    $script:optTimer.Interval = [TimeSpan]::FromMilliseconds(200)
    $script:optTimer.Add_Tick({ if ($script:adapters.Ready) { $script:optTimer.Stop(); & $script:optFill; if (-not $script:adapters.Error) { $script:optDlg.Hint.Text = '' } } })
    $script:optTimer.Start()
    $dlg.FindName('btnCancel').Add_Click({ param($s, $e) [Windows.Window]::GetWindow($s).Close() })
    $dlg.FindName('btnOk').Add_Click({
        param($s, $e)
        $w = [Windows.Window]::GetWindow($s)
        $sel = $w.FindName('dgIf').SelectedItem
        if ($null -eq $sel) { $w.FindName('tbHint').Text = 'Select an interface first.'; return }
        $useF = [bool]$w.FindName('cbFilter').IsChecked
        $expr = $w.FindName('tbCapFilter').Text.Trim()
        if ($useF -and -not $expr) { $w.FindName('tbHint').Text = 'Enter a filter expression, or untick the option.'; return }
        if ($useF) {
            $ferr = [PSShark.PacketFilter]::Check($expr)
            if ($ferr) { [void][Windows.MessageBox]::Show($w, "The capture filter is not valid:`n`n$ferr`n`nFilter: $expr", 'PSShark - Invalid capture filter', 'OK', 'Warning'); return }
        }
        $script:iface.Name = $sel.Name
        $script:iface.Promisc = [bool]$w.FindName('cbPromisc').IsChecked
        $script:iface.UseFilter = $useF
        $script:iface.Filter = $expr
        $w.DialogResult = $true
    })
    $result = $dlg.ShowDialog()
    $script:optTimer.Stop()
    return ($result -eq $true)
}

function Show-GoToDialog {
    $body = @'
<StackPanel>
    <TextBlock Text="Go to packet number:" Foreground="Cyan"/>
    <TextBox x:Name="tbNum" Margin="0,8,0,14" FontFamily="Consolas" FontSize="14"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="btnOk" Content="Go" Style="{StaticResource PurpleBtn}" Width="80" Margin="0,0,8,0"/>
        <Button x:Name="btnCancel" Content="Cancel" Style="{StaticResource PurpleBtn}" Width="80"/>
    </StackPanel>
</StackPanel>
'@
    $dlg = New-Dialog 'Go to Packet' 340 210 $body
    $dlg.Add_ContentRendered({ param($s, $e) $s.FindName('tbNum').Focus() })
    $dlg.FindName('btnOk').Add_Click({ param($s, $e) Invoke-GoToPacket ([Windows.Window]::GetWindow($s)) })
    $dlg.FindName('tbNum').Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { $e.Handled = $true; Invoke-GoToPacket ([Windows.Window]::GetWindow($s)) } })
    $dlg.FindName('btnCancel').Add_Click({ param($s, $e) [Windows.Window]::GetWindow($s).Close() })
    [void]$dlg.ShowDialog()
}

function Invoke-GoToPacket {
    param($Dialog)
    $tb = $Dialog.FindName('tbNum')
    $n = 0
    if ([int]::TryParse($tb.Text.Trim(), [ref]$n)) {
        $i = $script:store.IndexOfNo($n)
        if ($i -ge 0) { Select-PacketIndex $i; $Dialog.DialogResult = $true; return }
    }
    $tb.SelectAll()
    $ui.tbStatusMsg.Text = "Packet '$($tb.Text)' is not in the displayed list."
}

function Show-FindDialog {
    $body = @'
<StackPanel>
    <TextBlock Text="Find packet containing the text (any column):" Foreground="Cyan"/>
    <TextBox x:Name="tbText" Margin="0,8,0,14" FontFamily="Consolas" FontSize="14"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="btnOk" Content="Find" Style="{StaticResource PurpleBtn}" Width="80" Margin="0,0,8,0"/>
        <Button x:Name="btnCancel" Content="Cancel" Style="{StaticResource PurpleBtn}" Width="80"/>
    </StackPanel>
</StackPanel>
'@
    $dlg = New-Dialog 'Find Packet' 420 210 $body
    $dlg.FindName('tbText').Text = $script:lastFind
    $dlg.Add_ContentRendered({ param($s, $e) $s.FindName('tbText').Focus(); $s.FindName('tbText').SelectAll() })
    $dlg.FindName('btnOk').Add_Click({
        param($s, $e)
        $w = [Windows.Window]::GetWindow($s)
        $script:lastFind = $w.FindName('tbText').Text
        $w.DialogResult = $true
    })
    $dlg.FindName('tbText').Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { $e.Handled = $true; $script:lastFind = $s.Text; [Windows.Window]::GetWindow($s).DialogResult = $true } })
    $dlg.FindName('btnCancel').Add_Click({ param($s, $e) [Windows.Window]::GetWindow($s).Close() })
    if ($dlg.ShowDialog() -eq $true) { Find-Packet $true }
}

function Show-AdminNotice {
    $body = @'
<StackPanel Width="600">
    <TextBlock Text="PSShark is not running as Administrator." Foreground="Yellow" FontSize="15" FontWeight="Bold" TextWrapping="Wrap"/>
    <TextBlock Margin="0,10,0,0" Foreground="#E8E8FF" TextWrapping="Wrap"
               Text="Live packet capture needs Administrator rights. You can still open, view and save capture files (.pcap / .pcapng) without them."/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,22,0,0">
        <Button x:Name="btnElevate" Content="Restart as Administrator" Style="{StaticResource PurpleBtn}" Margin="0,0,8,0"/>
        <Button x:Name="btnContinue" Content="Continue" Style="{StaticResource PurpleBtn}" Width="90" Margin="0,0,8,0"/>
        <Button x:Name="btnExit" Content="Exit" Style="{StaticResource PurpleBtn}" Width="80"/>
    </StackPanel>
</StackPanel>
'@
    $script:adminChoice = 'continue'
    $dlg = New-Dialog 'Administrator Rights' 660 260 $body
    $dlg.FindName('btnElevate').Add_Click({ param($s, $e) $script:adminChoice = 'elevate'; [Windows.Window]::GetWindow($s).Close() })
    $dlg.FindName('btnContinue').Add_Click({ param($s, $e) $script:adminChoice = 'continue'; [Windows.Window]::GetWindow($s).Close() })
    $dlg.FindName('btnExit').Add_Click({ param($s, $e) $script:adminChoice = 'exit'; [Windows.Window]::GetWindow($s).Close() })
    [void]$dlg.ShowDialog()
    return $script:adminChoice
}

function Show-AboutDialog {
    $body = @'
<StackPanel>
<Image x:Name="imgAbout" Width="84" Height="84" Margin="0,0,0,12" RenderOptions.BitmapScalingMode="HighQuality"/>
<Canvas Width="420" Height="300" Background="Gray">
    <TextBlock TextWrapping="Wrap" Background="Black" FontFamily="Courier New" Foreground="Yellow" Width="400" Height="280" Margin="10,10,0,0">
        <Run Foreground="Lime" FontSize="14" Text="PSShark (PowerShell Wireshark)"/>
        <LineBreak/><LineBreak/>
        <Run Text="A Wireshark-style packet capture viewer written in PowerShell (WPF + runspaces)."/>
        <LineBreak/><LineBreak/>
        <Run Foreground="Cyan" Text="Capture : NetEventPacketCapture (live, real-time ETW)"/>
        <LineBreak/>
        <Run Foreground="Cyan" Text="Files   : read pcap / pcapng, save pcap"/>
        <LineBreak/>
        <Run Foreground="Cyan" Text="Columns : No. Time Source Destination Protocol Length Info"/>
        <LineBreak/><LineBreak/>
        <Run Foreground="Lime" Text="Theme   : Midnight Violet"/>
        <LineBreak/>
        <Run Foreground="Lime" Text="Decode  : Wireshark packet-detail format"/>
        <LineBreak/><LineBreak/>
        <Run Foreground="Bisque" Text="Drop a .pcap/.pcapng file on the window to open it."/>
    </TextBlock>
</Canvas>
</StackPanel>
'@
    $dlg = New-Dialog 'About PSShark' 470 500 $body
    $dlg.FindName('imgAbout').Source = $script:appIcon
    [void]$dlg.ShowDialog()
}

function Save-Screenshot {
    param([string]$Path)
    $w = [int]$window.ActualWidth
    $h = [int]$window.ActualHeight
    $rtb = New-Object Windows.Media.Imaging.RenderTargetBitmap($w, $h, 96, 96, [Windows.Media.PixelFormats]::Pbgra32)
    $rtb.Render($window)
    $enc = New-Object Windows.Media.Imaging.PngBitmapEncoder
    $enc.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($rtb))
    $fs = [IO.File]::Create($Path)
    try { $enc.Save($fs) } finally { $fs.Close() }
}

############################################################################
# Embedded application icon (wireshark-icon.png recoloured green, base64)
############################################################################
$script:iconB64 = 'iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAYAAABccqhmAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAD7oSURBVHhe7Z13lBzVne81M9KMZkZxUuec42SNcgYJJWQQEkggsDHJ4F0/vBy8u9isd43BOAACyRiBECiMUM4oIYKc1okkBBiEwd73zu7bPX5ev0dXx9E73+qq1u1b1TM1qXu669Y5n/9mbndXfb+/e+/v/u6tUaNK8yofNWrUaL/fX2mxWMYajcZqnU5Xo9FoakFjY+M4UF9fP57BEPUg6gNagWagHWgIWhI0xa4ReJW1t7ePwcPCw6MfLoMxlEBj0Bo0B+3RYmTX8F+46aOHyvB1dXUTGOqF1kN/EQOCMEpgAWEYL970Sofudrt9otlsnqzX6+t1Ol2DRqNpampq0jQ2NmqB2WzWMRgioi6gEWgFmoF2oCFoidaXHNAmEQzYNQRXudPprOrL9IjkeFB4aHiA9MNlMIYCaAsag9b6Gj1As9Auyx0M7CpHEoa+qSSIyojQgzW8yWTSG41GA0N94NnTeugP0B402NcIAVpmgUDZVdGb8RF1+2N6PGSDwWDU6XRmjUZjbWpqsptMJofRaHQaDAYXgyECTUAb0Ai0As1AO9AQrSs5xGDQ28hACAQVtOjZ1UePjyEX5mX0TafBwxLMbmMmZwwV0BI0BW0pCQiCVifTOqYCARsRIGuKeRJ9g0jj99Xb6/V600ANr9fr3QIeoNPpvIzSR3ze4vOnddEXYkCA9mg9kgjazRkIhByBalcORudK7hmNxrreMvUYmmGYpsT0eMB46Fqt1qfRaAJGozFkMBjCer2+hcEQgSagDWgEWhECRZ/BQQgGVmiS1qkItAxN0zoH8IDaVg3Kcg33ES1zGR8JG61Wa8E8jX4ItOFFszOjMwYLNCQGhb4CArQpaFQ2uShoW3ZEIEwLSn40UCHX6yNxotVqG+kbRhq/t94ewzmtVuvvr+HD14RmT3tw9so5jy+88YotS+64avfKry8/ct03rz655mFG6YFni2d8xdald+CZ49lDA7QuegMag9agOVqHItBqb4EAWpdLFgqjgdJMEqKmmv7BQCi2kNwk3LzehvliT6/E9M1rO+ZdtXvF1685t3bjmrduPrbuw1vfXf/ZHf/nln+7M8VgQAvQBLQBjUAr0AytIxohGOQcGYjTg1yBANqn/QCE/Qclc5VhcwX9I7F2mivBJ2Rbcxnfo9FogvTDIAks889csvvq+677zU27b/z49o9v/uPtqZv/dAeDoZw/3p6CdqAhaAmaonVGImhSdlQALUPTtM4BPCBXRwDPlMKUoFyuXh/zIPpGACRScs3xkZTpzfieK73Tlx9f9S83fPCl3978xzsT6/90R4rBGCqgKWgLGoPWaP2RgQBapfULBG3nShZKcgPwTjEvF5bLzfeFUsqsHy8O9+kbBhBVkZ2lbzQwmx1tS3Ze89U1b9986qbPbvv8pj/elmIwhp3PbvscmoP2oEFal0DQrOyIINe0AN6g/SLkBYouCEiSfUh6yA35c/X6mFch+0rfWGAPBjtWnLjuoRsv3vZHycNhMPIINAgtQpO0ToGgYUmOINdoAB6hE4TFlhwcTUcxzHHklveEcktJhBSSe830zfROmTH16ldWP37jJ7f9+42f3ZpiMEYMn9z279AmNErrFloWNC3RulxuAF6RywsUQ71ABf2l5cwvDPlt9M1ApJQb7lssltblJ1c/vO6TW/+87rNbUwzGiOWTW/8MrUKztI4FbUtGA/ACPSXoJQiM2JGAZM5vsVgm0dFN2IUlGfLn6vVn/3DB2us//OK76z77cqrffHorgzF4aF0pAJqFdmk95xoNCJvUJPsM4CHSUyM1J6DY/HLLe3Jzff+y8MxVv1q3e+1nX46v/exLKcV8ymAMI7TeeuXLcWgYWqb1LVSqZvkA3ijGIFBGL/XJmV/YWpll/lxD/nkbrli/5uNb/ucNn30xpYhPb2Ew8g+twxxAy9A0rXO5KYHgEUlykA4CwhJh4esE6CIfuTl/DvNjiURSxbfildWP3fDpl6LXf3pLqk/+cDODUXhoXcoATUPbtN4FD2QtF8oFAbmcgFAsVLiL3sqL5Yt+mD9rvh+6pnX2qnduen3Np7ek+uQPNzMYIw9apzJA49A6FQTgBUVBgF4iFLYUF+SSZPzpdX65Ob9QJZVl/q77ZqxY/dHNf6JvlgT6hjMYIxFatxTX/f6mP0LzdBCgKwjlcgLwGO27QqwMlNFJP3o3n1Lzz/nBlTdcd/Hm/1z96c2pnPxhPYNRfNA6JoDmof2BBAF4jfSekBTMXz6A3s9P1/ZjTZNe6pMb9s/fvOiO1RfX//W6P6xPyfLJTQxG8UPrWgDahwfoIEBPB+Aluk6A3jsgnCcw/BfeiEJ+sHD+PvnFMEyx92X+K7qX3XvdxZsiq/5wY0qWT9YxGKUDrW8BeABe6CsIwFO0z+ikoPC2omG9JEN/et6PgxAo82OZIyvbP//ZxXdee/Em7tpP1qUYDNVz8SYOnqCCADyTtUQIb1EdbVY+YNinAnTWnz7MA1lL8gsLZJl/9qPz1q66uP6vkpvA34i1BQbfgVH60M89z9C6xwjh4vq/wht0EJDxU9bKAH2oyHCuCpSTH0QP/YUXbGQl/egKP2Q+r/n4xv+65pN1KQkX1zIY6oHWP/j4xv+iVwfoikF4jM4H0FOBYakSpAt+6HP66c09wlFJmR8SWNMyd+UH1//pCxdvSEn4+PphAO0yGEMFra8hgPbBxRtS8Ai8QnqH3jsAr1HeayK9ORwFQllr/nTWnx76yyX9Vry95twXLq5NSZDc6MGA9hiM4YbW3SCg/XBxbQpeIb0jlxSkpwL0qsCQ1gaQvb9ctR+95EfX9y86s3LDSkQ3mo+vHyLQFoORb2gdDhDaFxdvSMEzpIeE91lkPAbPkR6kqwSHchSQ1fvTiT86608P/advmHPLiotr4isurkll8fFQcP2Qs/zj1allH13HKEHwbOnnPTTQuhwAtD8uronDO6SX6KkAvSpAJwSHZBRAF/2QvT9d7ScsW2SG/r4VodnLPlj9vyQ/9qPVgwD/33+Wf7Q6teT316au/HBFav6HS1NzPrgqNeP9K1LT31+YmnphXqrrwtzUFIYqwLPGM8ezhwagBWgC2oBGoBVaP8qh9doPKJ/AO/AQNRXILA3SVYLwJunVoSgOyur98XojMuLQB3nSWf+rfnnNvuUfrUpmszovLPtoVXLR71cm536wJDn9/SuSnRfmMhiKgWagHWgIWqL1NXxk+wUeIj1FrwrAg6Qn6VeQDWoUYLFYxubq/bEUQX4R4V1qmS869bFZ61d8vDYh/YFrho0lv782Of/D5ckZ71+Z7Lwwj8EYMqApaAsao3U3tGT7BR6Cl0hv0fsFyGVBehQAD9O+VnyRVX999f5k4g9HJS89f92FZR9dl8wGPfPQsvT3q5ILPlzBTM/IG9AaNAft0XocGrJ9Ay+Rx4/TCcHeRgFCdeCArqzTfcmSX7roh+795x9b/P2lv782mc2qIWXxh19Iznp/cXLKe/OSne/NZTDyDrQHDUKLtD4HT7Z/4KlcowC6OIguER7QacJk8o+u+qMz/2Tv717mn7n0g1V/WfLhF5KXuWbIuPLDq5Mz31+U7HhvDoMxYoAmoU1ar4PjsofgKXgr1yiAXhEgqwMHkgwsIyMIvfTXa+9/asnGqz78QnKowc2dceEKyY1nMEYS0Ci0Sut3KIC3ehsFkB6VWRJUvkmI3vJLJv/0er0pV+9v77J2Lbqw8j8xJLrMNYNm9vtLkh3vzWUwigZoltbxwLjsJXgLHss1CoA3RZ/SycB+bRUmh//0Cb9kzT/KE8mINPvYokeH0vzzP1jOz7Pom8tgFAPQLjRM67r/XPYUPEZ6jiwRpvcIkCcJ92saQGb/yZd50sk/rVbrF7+I2Rtqv/L8yn9b9MHVycusHBBXfrAyOf29hcmO83MYjKIHWoamaZ0r57Kn4DF4TfQdPEhOA8hkIPmy0f6sBmRt+yWz/zLv8svs9Z+xff7fXYkvmCFt5P4y//1lySnn50luIoNRzEDT0Datd+Vc9ha8JvqOPjOAfNegzGpA39uE/X5/pfgP2FxADinIo77o5N/CX1396mDNP/vCVZIbx2CUEtA4rXvlpP0Fr5HeI5OB9NFh5AYheJv2u+Qi5//0tl9y+E+W/XqvC89Z+MHV0YUfLE9mc7UiFry/PDn1vQXJ9vNzGIySB1qH5mkf5Ebiqyg8J/qPLA+mVwPIbcKK8gDk/J886pve809u+plxeP73FlxYkpSyrE/mX1iW7Do/X3KTGIxSBpqH9mk/yEP7akkSniOmAc2UNzNnBZBHiCvJA2St/5PLf2TxD539n/+7Ze9Kv/TyPpl3YWlyCjM/Q6VA+/AA7Qt5sv0Fz5EeJFcDyKIgejmwr3qAzO6/3ub/5J7/wJebF82/sDSZTbpn7425F5YmO8/PldwUBkNNwAPwAu0PebJ9Bu+JPiTPCugtD9Dr7kCyAIhc/6d3/mk0mqD4wV0vzfrmvAtLktks7RX8YCRE6JvBYKgReAGeoH0iJdtn8J7oQ3iS9Ci5HEjWA/RaEEQe+03u/sOhA2Tj5Px/5rmFB+e9tzR5mWW9Mve9pcnOd+cl29+dw2AwBOAJeIP2i5TLXoP3RB/SeQDyoBByd2Cvx4aTKwBk/T9Z/kvP/2e/tfhPcy8sTeRizntLkiSd5+cl296dzWAwKOAN2i+0n0jgPdKLZB6ALAsm9wX0uhJAHv5JrgCQCUBy/h+8p2Up/aWyvuB7i5MkmO/QP5rBYFwGHqF9Q/uKBB4U/UjmAchEILkS0OthoRqNplb8Q7ICkKz/J8t/O3fNemD2hasSOSF+xNTzCyQ/lsFgSIFXsoIA7SsCeJAIAJmyYHJfAFkRCI/Tvs9cZA0AdfxX5thvMgE49dS852a9tzghy/lFSZHp56+Q/EgGg5EbeIb0kMRfAvCg6EcyEUgeG04uBfZaC0AGAPGfAfXKr0z9//SfLzwz6zzMLksSzDy/ONn+zpxk2zuzGQyGQuAZeEf0kYy/eOBB0Y/kvgC6IlBRABD/iA4AhPmzVgBm/O6Kj2aeX5SQISnS8e5cyY9jMBh9A++QXpLxWQIeJAJA1kqAXAAAtO/FK1MFSBYBkTUAOJNc/DCdw9E2891FkRn4ElKSoOvdBZIfxWAwlAMPiX6S8VkCHoQXRV+S7w0gawGoYiDZakAlASCzBOi/t3nFtPMLEzIkRVrfmcVgMAYJ6SkZvyXgRSIAZJYCBxwAyENAySIgMgCEH+1cP+3dhQkZkqDjnXnJ1rdnMRh5oeXXM5Kh16Ym/cc7k749bSnvS62p1rekf1eMwEuir2T8loAX5QIAWQxEHhLarwBA7gIkzwAIb5xy59R3FyYokmDKO/MlP4LB6C/hn05Lwsj2HwVSxq/bU4036HsmzqnvqQ2P76l21vZU6qouVUwcfalsdNmlUaNGSagyVl/S32NJBc90SdouNuAp0V+078KbptyVmZpnvzQksytw6APAls57p76zIEGRBG1vz5b8AAYjF8GzU5KOJ4Mp3R2Wnknz63tqvON6KsaPlhh6oJTXVFwKvlLcQQCeEv1F+w5ezEsAIKsAW7qnfbPrnfkJgiToZEN/Ri+Ez01POp8OpdAzw+yV2iqJYYeD+pXaHvq7FBvwlugz0nvwouhL6g3CwxcAWvfNeHjK2/MSBEnQ9tbsZOtbMxkMnuZfTk86ngikGlZpe6pM1RJj5o3yskveXW0p+vsVE/CW6DPSe/Bi/gPAgemPd7w9J3GZucn2t+cmW96ayVA5/qMdSeN9jtSE6ZN7yivLpWYsEOZvuVL0dy024DF4jfQevJj3ANC8v2sDaX6ArCv9hRnqAL1r03pDT5VlrMR4IwX3iy1FHwDgMdFvov/gxbwHgJYD059sf3tOIs1cPklBf1lGaRN8rYvv6au9tT202UYioXNTJb+hGIHX4DnRf/Bi3gNA+MDUJ9venpVIg3k/6/3VQPPvZiQdTwVTkxY29JSNkV9+G4lUu2p7mn8zQ/J7ihF4DZ4T/Qcv5j0AhPZPeaLtzZkJkZY3pzNKmODZjoT2dnNqTGOlxFzFgPURd7L5N9Mkv6tYIb0HL+Y/AOzp2ND65qyESMubMxglSOBEZ6JprSFVXj1yknn9pbZ1fE/gVEei5bfS31eskN6DF/MeAAJ7Op6kvxSjdPAf6kjWX92UGgnD/LKK8kuVmuqemuD4nolz61JjjdXKcw7lZZccG/zJ4KkpieZfo/eU/tZiB14sSABofnN6glFaePe2JyddWd8D40jMNMyMnlB5qbZtXE/DdbqU/m9sSfO/OJOOzcGEd19rwncgjXNLONGf0QgCBv4vcKYjEf7NNMnvLQUKEwB2tz/Z/LtpCUZpEHilPVF/TVOqLE/Gh4mr/eN66lc0pQx/Z0s6fxJM+va3Jvpi8qKGFN1WLsrHll9yPhtM+A62JgKn2hPNv50u+d2lALzIAgBjQIR/NTVhuNeWGsrae1nKRl3CBp7G1YaU9XvupA+9uozBe8O9o3+9f8O12hT+z3+sLRE42cH/Vvr3lwKFCQC72p9q/h0iKqNYsT/hS1ZZ+jGf7icVtRWXxs+c3IPhvOv55oRvf1vfYKh/qC3hP9KR8B9tT/iPtSf8xzsSgZc7E/q7bYp7/9ETx1zy7Gjh20IiM3h2SiL8a+k9KAXgxbwHAH9320b6izCKA//RKUmU6dKmGQrQQ2Pebf5nV9K7T8bgWWZvE8yeNjpMDrPmotpWo/g76263pPAZAQSPkx2J0BtdiebfSO9FKQAv5j8A7GzbxM+pGEWF6R+dqfIa5cNoRWB47x/Xo7/bmuJ7XQzv5YDpYfijbYkAb3j07Mqw/ciblHxuDqoM1T3evRhJtPL/i94/dK5Lci9KBXiRBQBGr/hPtCcmzKhT3IMqYUxd1aWGVbqUY6M/PaeX40Brwn+4TejhpcaW5URHAuv2gdMdieCZ9PB98pWNir+77svS3j/0i6mSe1IqFCwAhH87LcEY+VgecicrJlRIjDJQKnVje3R3WlKe3S38Ep0EzOOPtPFzd//LfXCiI+GH2c90JgKvdSWCr3clgm9MycJ3tDVRVqlsdQJTENf25vTnI5i8NiURPNeVCP9muuS+lAosADBkgfgnXdGguOfsi7HmsT36e21Jz14Z4+9vSfgOC0k72uRZhm9PBE53JgJnOxNBmJMyuxy6u82Kk38TF9Sl8F34zzrVwf9/6JdTJfemlChMANjR9mP6izBGDt6D7ckq89ghMX+1e1yP4e/tfFJPYvyDrQnf0XRvK4vYw7+i3PA857oSwZ92JYI/60r0Z6XC+n13Uuz9gxhRnJsiuTelBrxYmADwm2l8dRVjZOH4iT+JwzJpc/SXSs3YHsN9tqTE9JjbH8T6OpboZOB733ahl+9MBF+f0jsw/E+nJEI/70qE/nVqIvxr4rf82K84+VftGteD78Z/r1PtfNuhX2L4L71HpQQLAIwM5gedycHW72Me3bTWmPLsapYaH1n8XMY/2Z7u6WmD05zrTJsd5vzVVMlvIOHLkmW+oxyoE8CIJN3743OmSNorRQoYAKankyuMwvPr6YmmLxoVz5VlKUvXzjufCyfSw30R0vgd2SDRdho9vZDAkwM9/M9gePTuMt89B8jcK638G11Tccnd3cJPRwKnEWiE0YRMu6VGYQLA9vZNoV91xRmFJ/jTrjiSX7Qp+kOVvrrH/F13wrOvNU7iPdQW9x1rl3KiPe5/pTMeeDUHr3fGgz+dEg/+York+yrFtsmfoL9nLiYvaUh59rfy3y1wtjMeeKNT0l6pAi/mPwBsa9sU+tcpcUZh8R1vi9cExiseJksoG3Vp0uK6lGtnOMv4ngOtcd9RGfO/3Bb3n+mQGp6nIx48J5he5rv2l8a1esVBzfqEN8EHq5fb+O8S+kWXpL1SBV5kAUCFuHaGE2O0lQM2/5iGyh7jtxxUr98S9x5ukRqf7/FzGB+9/c+k32+wjLUrK/2ttlb34LsjYPlPd8QDb3RI2iplWABQIdbHvYny2oEX90yYOznl3Bbse7iPHlV2qN/BD/FDvxyentZ7uEXx8L9+ZVPKcwBBK937B38uba+UKWAAmBpn5B/D/fbkQPft43Qd7e3mZFavj7nzEcr8xzuEof4UCsztuwTjS7/bUGH4hl3x8p/x286E93Br3H+yIx54DaaQtlfKFC4AQASMvGK436bYGDRjqisuGf7RmvDsbY2LeA+2pef6BLyRkEgj4Y0v9Ph5YMKcyYrm/xXV5ZfcLzXz3xsjFeQg6LZKHRYAVILlYdeAe/7KprE9lh+5L5t/X0vcd5gy/omO9HC/gMYH+DylOxZrO8elvAfa4r7j6ex/6BdTJe2VOgUJAN5tzZuCv5wSZ+QH29M+xRtiaFAhZ9/sjbv3NvMgw+89SnCsLe473R73n+3IInCuU/I98kF/lv80t5mTHiQtT7enk5Ey7ZU68CILACWMc0coUTFuYKW946ZN5Jf4MuY/SJn/5VY+u59l/tfb+aU8+nvki8Z1/Vj+2+hN4HfwAevnLADkMQC0bApiuMYYVjwHWxJjGge21Fd3dWPKvac17t7bwuM5DNO3CbTGfac74/6zBK/BRBCV9HvkExz/Tf8WOVC85MZU5uX2uB+rEjJtqQF4sTABAL0EY9jwnWyPV1mV74QTKRtddkl3lzXp3tMS59nbHPcebo97j7SmOZYu5uF7fgFUztGfXxB+3qV4/j9pcX2KL1g62Z6ertBtqQQWAEoQ9MZKe0IS1MSjuCdjfr6wRzA+ON6WZXz/2Xa+iIf+/ELh3hdWPP83fMOWXv4708Gv/dNtqQUWAEqMwM+mxMfPmNRv8+MUXssPPdnmF41/pDVdxkv2+kiayXx+IbE84lK8zOl4PpAezbzWIWlHTRQsAAR+0RlnDD2Tlyp/+YUIXoJh/I4j4doTjgP3/ua450hLBu/JtrjvlfY0Z9vj/p91SD53JNB0u1FRABhTV9Xj3tcc955oi/vPjczfki8KEwBeaN0UQG/FGFIa1yvPgIuguk9/vyXh2tMcB+6DMH2rQEvcewrm70jzajuf6KM/d6QwYZ6yAqDq5toe/E4vlv9G8O/JB/AiCwAlgPFB5eWvGcpGXdLebU1mzH+IMD+f6UevL5j/tXbJZ440lB5jNnlFY4pf/8fyn0w7aoIFgBLAtS88oM09jesMl81P9vzHWuO+M4LxMed/feQbxf96Z1xppaPuq7ak53hrUfyu4aZgASD4864YY/AEftoZG0jGf9KS+qRrdzgG3PvDMc+RFh7v8baY75X2DIE3OiSfORKxb/HH6d+YC/P3XchrxALniuO3DScsABQ5Tbea+j30HzdzYsq1SzD/PsL8J0jzF5dBDP9gVbQEiJyHqzsY851pl7ShRgoXAH7WFWMMDttPfIqHvSLV4dqUc3sohgDg3tcS8xxO4325jTcFzyvtseC5TsnnjWTq12gVBcIqw9gejHh8Z9slbaiRggQAzwstmwI/mxJjDBzvmbZYpV5Z0kuk2lHTY98aiDl3hWLOvaGY+3Azj+d4K98ez9k2flpBf95IZ8KcSYpWAGqxv+FwOOZ7rU3ShhqBF1kAKEJQykqLuzcqtWN7bM/40ubfE8yY332s+bL5X22VfE6xUNOsLA+C3IfnWCs/vaHbUCMsABQhxn92KprvimDea/iOPc6bf3cw5j4kmP9oaZgfVJmV7XtouEGf9Jxokfy/WilMAHi+ZRM/zGT0G9f+5nh/t/fWr9Ylnd0hvvd3H2wWAkA45j3VFvOebot5kfCT+axiQukLTDV3GhOeUy2S/1cr8CILAMXCGx2xmhZlQ12Rau+4HueOUMzZHYy5D4jmb75s/jMYDst8VhHhe70thqIm+rfLof+GNcEvb8q0o0ZYACgiNHeYFWW6RUZXl1+ybHDF0fu79oXT5j8UjmENPG1+LPVJP6fYcB9uUVwDYHzEjpJmSRtqpSABwPV8eJPvp20xhnLs2wNx7NWnBd0b2ruNCUd3kE/6uQ6FY65DoZj7ZEvMc7o15jndEvO9If2cYsT2gk9xALBu9sa9r7dK2lAr8GJhAsC5thhDObVTxvcr649iH8fOQMzRHYi5DgRjroOhmPvl5hjmv55Tzfywmf6MYsXymEdxUtS5N5gOfDLtqJECBoD2GEMZ5kfdigUOxjRW9die9cUcO4Mx5/5QzHUwzC/3eU618nhfa5V8RjFj+JZN0f3By0LdR1sk/69mWAAY4cCsleYqxYm/svJRl/QP2uO8+femzY/Cl4z5Xy0t8wPNVy2KciOohXC/zAIACQsAIxzt3yoTt8jklY1JmN+xC8P+MD/095wUzY9hn/Qzip2m25Xth8AR58h/0P+vZlgAGMG4j7fEKiYoX/MfaxnbY98WiGHu7zoA84f5Nnjzny1N84OmW5WdBFTtH5/yYqOTTBtqpXABAIkYRq/UXdOkSNgi+m/Z4o4dwtD/AGr9w0LvL2T8S5TGLyoMAIFxKT4QyrShVgoWALxvtMUYubHvCMRRwkuLOBc1XeNS9h0BfujvPBCKOZH1P9ESc59sjnlfk7ZfSjTcrFcWAILjUp5XWyX/r2YKEwC2hFgA6INxUycqXvYrqyy/ZHrcGbfvDPBZfwQA18vN6TX/s6Uv+IablAaA2pTn1RbJ/6sZeJEFgBGG+YfK17XBpBUNSb7335fu/V1Hw7z53afVIfaGdTplASA0LoVVFfr/1UzhAsDrrTGGDK+2xvrzRp/Rkyp7rM96Y/ad/phzfzDmPBhMD/1PhPklREn7JUj9DcoCQE1ofDoAyLShVlgAGGHo7jP3q/dvuk2fsG8PxJz7wjHn/kAM69wIAJ6zLZK2S5X665VNAWrC41L0/6qdAgWA8Cbv620xBsVrbbFKk/Kin7HW6h77Nqz5h9IVf0fCafOfxsOVab9EwXZn+t7IkQ4A0v9XM/BiQQKA5/XWGCMbw3cc/er9dd+yxW3bffzc33EgEHOdaI65TjbHPK9J2y5l6q9VFgBqmyek6P9VO4UJAM8GN3lea4kxsqn21yru/bHsZ9vmj9l3IfkXiDmPBtOZ/7MIANK2S5m6NcoCQI2vtof+X7UDL7IAMAIwbXAq3tKKZT/jY3ah9w+ke3+Y/7T6zA8avmRQFACqLNUsAFCwADBCGDdN+br/hEV1Sb7335Pu/V3HwjHXiXAMa9x0u2qg6R6doqnTmPoqFgAoChQAwpv4eSqDx4oDLRQeaYXqQOMTzrhthz+97o+DPtD7v4IHKm1bDWi/oWzlpLym4hL9v2oHXmQBoMBMXFSnuPevnTGBn/s79obSvf9xIvGnUvTfsSuePrnPqjdQylG4AIDhKgNG7tdRX/qHbHF7pvcP8QHA/UqzpF01YXrCoTgAYMRE/7+aKUgAcDwb3OR+tTnGaI7VKXylFcBrvazbfDH7Hn/Mvs8fcx4Px1wnw5I21YZli0txALBu98bp/1cz8GKBAkBLTO04j4Vj5TXKd/zp/t6SwNzfjsz/kSAfADCkpdtVG7a9/hh9r3Jh3uSK0/+vZlgAKCCNdyrbxw7G2qp70Pvbdgdi9v2BdO9/ClFc2q7aQCBVOo0yPupK0P+vZgoTAJ7xswDwakus0qT85Z6au40J6zZvzL7XH3McTgcA1vunwb2omDBa0b3Uft3MAgABvMgCQAEwPam88GeMpqrHutUbs+0S5v7HQjHXadb7iziPB2M4Do2+b3LUr9Ml6f9XM4UJAJuDGz2vtkXVzMQl9YqH/w03a9H7R+17AlHHwWDU9XKzpD014z7ZGq3uqFG0lDphQV2S/n81Ay/mPQDYNwc2uvHgVIrrZGu0vFbZyywrqssvmZ91Ra3d3qhtjz/qOBqKuk63SNpUM65TrdEJi+sUBVScCkT/v5qBF/MfAJ7xb3SfbY2qFe0/WBQP/8fNnpS0bPNGbbv9UfuBAB8A6PbUjutUS7TuRo2iasAxTZU99P+rGXiRBYA8U9Ou/DVfum9a49YdQu9/JMiLnW5P9ZxpjWruVRZU8eIU1+lmaRsqhQWAPINEntK6/0rd2B7Li56o7SVf1L5f6P1fYQFAwpmWqP4Ru+JaAOsOX0zShkphASDPNHxJq2ioCiavakpYt3n44b/jcDDqOsnML8srrVHzFneUvn+5MPzQFpe0oVIKGADaomqk0qhsuQpDVcMTzhiSf/Z9gajjCHp/aXuMNAiSo6uVVVU2/Y0hQf+/WilMAHjatxFRW20Y+7FppTpUm7K86OWH/45DIX7pj26PcRn7nmC0yqwsuE5cVJ+k/1+twIsFCQCuV1qiaqM/a/+Nd5vilu0ePvlnPxyIus5I22NcxrbfH62ZNk7R/a2yV/fQ/69WWADIF2daoqPrKhX1UKNrKi6ZnnVGrd0eXtiOYyFpe4ws7IeD0bp1yvIrOFSF3dM0LADkCeNTLsVZ6nHzJiXN2zxR625vuvc/LW2PkY3jaDiKU5Lpe5kLTMfoNtRIgQJAYCM/pFURdTdoFA1Pge6btsvDf6z9y7THyAY9uvk5d1TpC1Ub79In6DbUCLzIAkAeqLQqe+HH6ImVPeatHn74bz8QjDpOhCVtMaTgPiFoVilcZRm/YFKSbkONsACQBywvepUP/+ekS3/54f8hYfgv0yaD4mRL1NLtidbOnKhopFVpHtsjaUOFFCwAOM6Eo2qh4S5lx1aDpv9hipt3uKLWvb6o/WhQ0hYjB6fDfNCsW69sTwCqMW2HA9J2VEbhAsDp9ENTA9XN4xTV/pdXV1wybnbyPZntQCBqPxGUtMXIjXWvP6r7J6vi0Zb+B/Y43YbaYAFgmLHtDyhOTFW316bMwvDfdiggaYvRO9YDvqhpiyuq9Hiwhtt0CboNtVGwAOA8FebUgOYbynap8YK8VRc37/Bxtn0BznE0JGmL0TuOwyHOvN3HVVnHKhpxjZs9MUm3oTZYABhmkNSjhScHav/1Tzqi1m4/Zz8Q4JwnpG0xesdxLMRZuwOK7/kYfVUP3YbaYAFgmKmoU3ZYZbV3fMr8oo+z7Qlx9sNBSTuMvnG8HObvX/0tWmWjLiQC9wejdDtqojABYFNgo/NkM1fqmLZ4FG9RnbymKWHe5uNse4N8T0a3xVDAiWY+AOi+bVN833WP2GKSdlQEvJj3AGDd5NvoOBniSp3GvzUp64lwXPV3rFHzTh9nOxDgHCfCkrYYyrDu93OmrV6urEpZ4rXuZm2CbkNNwIssAAwTSueiONMeorW+FOTsh4KSdhjKwf0zbfNwY53KTgkeG6hJ0W2oCRYAhpHR9WOUzf87apKmF72cdY+fsx9lAWAw4P6Zu/3cuAXKgi+Sr6gfoNtRC4ULACdCXCljel75EVWT1zXFzds9nG2fn3McD0raYijHfizAWV8KcI33GBQXBGnut8TpdtRCAQNAOD3XLVEav6Z8/q/7F3vUvMvP2Q4K83/GwHk5zFn3BDjj026urFJZHgBTNUk7KoEFgGFi/LzJioagFRPGpOf/e4Kc/QiisrQtRv9AIZXpBS9XHVRYgj2+osdxXNqOGihYALCfCHKlzBidsu2/1R21SeOLHs66L8jZj4ck7TD6j+2gnzNu83CT12qUj8J+YIvR7agBFgCGAesBP6f07H/M/007vPz/0O0wBobtSIAzdXs53ffsivMwk1Y3Jeh21EBhAsBT3o32l4NcqaL7oU1xAkr7T9aoeZeXsx3yS9phDAzbUT9nfsnHGbe4uEqDsgNCKi1je+h21AC8WKAAEOJKlYavGBUNPZGkMj7r5sy7/ZztaEDSDmOAHA9x5j1+zviChxu/uE7Z+QCjRl0yveCJStoqcVgAGAbGL1KWAKwyj00Zsf6/D6JFRJa2xRgYfEXgNg/XdJ9R8WgMgZtup9RhAWAYqPIoq0KrmT4+adqeLv+l22AMDiypoiDIsNnFVdSUK5oG1HSMT9HtlDqFCwDo8UqRY0HFdeiT1jTGzd0+znYoIG2HMSiQUxHzANWdtYpGZJiSWfeq61kUJACYn3RttB0PcKWI4RmH4sxz432GmOklL2c94pO0wxgkSATu8XGGF11c3a3KlwPr7zHEJW2VMPBigQJAkCtFmvpxApD+KWcUySrbMTwMaVuMwWHe7+WMO7yc7nF7FDX/9P2Xo8pdnaLbKWVYABhisJ5Mi0qO0fWVPYYXPHyyim6DMTRYD/o50y4fZ3jOqXh3INA/7YjSbZUqhQsA6PVKkOoOZeWn1eFxKb4C8KAwAmAMOdbDfs6028cZtrq5STc0KR6ZTfxCY4Juq1RhAWCIqahXdgTY+KWTE3wF4GEWAIYT8950WTA/DVC4Oahi0ugetTwXFgCGEFO3S3ECsP4OXdyECsCj0nYYQwdKrE07vZxhs5PDuQv0c8hF0wOmGN1WKVKgAODZaDsW5EoN7SP9KAH+rjVq2u2VtMEYWqyHAhwCrWGLE0e0KX4+NV0TUnRbpQi8mPcAYH3SxweASuvYnjGGqpJB6QnAZWPLLumfc3Lm/X7Oil6KMXwcDXAmfjnQzel/4uRG1ynbpYlVA/r5lhLwHjwILxYgAHg2Yp22bIyyN7iUGpXGypR+q5MzH/By1qN+xjBj3ufjjNs9nH6zgxu3ZJKiVZpSB96DB+HF/AeADd5NOLtNrQGgOlybNG5zc+ZDHolYGUMPAq2x28Mh6GofskWVbtUuZeA9eBBeZAEgz9TOnZQ07kyvAGCIyhhmDgfTy4HCNGCsp1bRUm0pU9gA8KR3k+NoWLUBYMJ1DQnjLgz/ZcTKGBZMe72ccbuX0z/r4CbforwmoFSB9+BBeDHvAcD+ZHCj40hItQGg7k5t3Lzbx1mP+Bl5gi8L7vbwRUG6DTauvFpZTUCpwgeAIyEOXsx7ALA+5v2RWgMAfrPmYUvUtN/DmY94GfnikJcz7nZz+hddnP4nDq565njFNQGliBgA4MX8B4BHPA+pNQAgC63f4uBMB1gAyDeYBhh2eDj9cw5O811LtGK8she3lCKZAPCI56H8B4Bvex5wHFFfDmB0Q2WP7kk7p3/BxZkP+TjzEUY+QdBF7gX3X/e0ncN2bLVpUCQdAMIcvJiXAKDT6bziB1nud3/debglUjZGHfMwnEhTPXNcoulbZk73tCNi2OqIWA75IpbDfkY+ORSImHa5I4atzoj+GWcEz2LylzWxionqGwkgAMCD8KLoS3h0SAOA0Qj/pxvU6/WeTAD4quMufHj9Ol287npNNms08UnXN8UnXt9YEtR/RR/TPWXnxQb0z9gjpu0uqTgZecG8xxsxbHNG9M/ZMs8EIDhPurEpRj+/Ygdegqdon8F7fAD4quMu0ZfwqOhXeHdAAaCurm5CXwHAvN5+o+tQS8TyY2/E8mOfBPPT3qyHUzrYI/ot9ohpp1siTEZ+MB/wRUzd7oj+eUdE/2x2EChF4CXaX2m8EXgQXuwrAMDTAwoAJpNJTwQAt/hBBrt7vvNg+P/lCgDA8LRL8mOKGf1PnLzgIDzzbq9EmIz8wU8DXnCmg8Dmy6OzUgMeon1FBgB4EF4kAoBb9Cu8258AMEr8AyD+IyDmFKAZH6TVamc7Xwp/atnsi1h+4s0JP097xlHcbEav70iLDbzgiJj2eSNm9EaMgmDa64nodxDPZIsjosNoYHMJ6E0A3qH9lMVmXwQehBf5TtlgaCa9SnqY9Dbt+8zV2Ng4Ti4AGI1GJ9FwWEg2zLJvDfzCusUX6Q3LFu/lh1QiGHY6I6b9LAAUlIP+iGGXK6JHLkDmGZUC8A7tJxp4EF4UAkCYGP475QIAPE77PnORAaCxsVFLTAMcYsMajSYoBICZtg3e/bbnfBHbc/5eMW/xSH5c0bLdwQvPfEBGlIy8YtrtTQeBF0svCMAztI+k+CLwILwIT8KbxPDfIfoXXlYUADQaTa34h01NTRqxAY1GYxMb1mq1fjEAWB90PWXb6udsWwJ9YnreHdFvdRQnLzj44SbEBiA8WoyM/INRmPhMDDuc6dEAnhX9/IoMeIX2jyxb/Rw8KAYAeJPoqG2if+Fl0dfwOO37zEUGAI1G0yQ2oNVqLUQA4IuB8KHm6+1/4+gOc0ox7fJcfmBFDIaftBgZhcG0pzQ0JQKP0L7pDXiQCACZIiB4lujAmxQFAKPRWC3+oU6naxAb0Ol0ZrFhohhomk5nutr+QvB/O3aGOSXYd4Y4U7cnYuh2FS0QnPmQnzGC4FcEZJ5VsQFvwCO0b3IB78GD8KLQKWeKgOBZwr8Noq/hcdr3mcvpdFYRf1gnNkBWAwpgJQAfutz6hO+cfUeIU4ptZ4jTdzsjxQQfnfe6IyasPx9ijDgO+iKGva6IYXfaSPTzKxbgDdovvfJE4Bw8CC/SKwBkFSC8LPoaHqd9n7na29vHiH9osVgmiQ2QtQDAaDSGDAbDVIPBsNT6bc8m5/4w1x8cB5qlD5HBUDHwBO2TvoD34EF4UfBkxqNkDQC8LPoaHqd9T14V4h+SxUBCEMisBAjJhqlarfYq00rLXa59zVx/cewPS24Cg6FG4AXaH0qA9+BBwYuZBCC5AgCoIqAK2vTklakGBORSoEajsYofIMw18KGL9Xr9CseO4B/oL6cEx/4Qx8/hZG4Kg1HqQPvwAO0LJcBz8B48CC+S8394VfQtuQQoBAD5KkDxImsBtFpto9iQXq83UdOAKTqd7kp8Cfsjvu2uvc3cQHDsDXHIqmMex2CoBWge2qf9oBR4Dt6DB+FF0pvwquhbeJjo0HPXAIiXTqerEf+BTATSeQC9Xt+q1+sX4kuYr7J/2bW7OeLa08oNBOfeFg6FNfRNYjBKEWgdmqd9oJjdzRF4Dt4TPNhKepOc/5MJQHib9rvk8vv9leI/kNuCQVNTk50YASDpMB9JCH4a8Kz/TckX7QfOPc2cdX9QcrMYjFICGofWaf33B3gNnhMSgPPJBCA8SnqW3AYMb9N+l7syiUBh2JDJA9AFQQaDYa6YB7A84N7g3BWMDBbbHn/EuN/9OYNRakDbtN4HArxGzP/hQdkCIJn5f68JwMyVKw9ATgOQdNDpdDPEPIA+rF/j2B78T2d3KDJYHLuC2O31uXEfg1H8QMvQNK3zgQCPwWvi/F/wYCYBSA7/+z3/Fy+yItBsNk+WmwbgQ4VE4BVCMcIK2yPeXc6dochQ4NgZiFh3+yU3k8EoJqBhaJnW90CBx4S5/3J4T/AgHwDo4T+8K/q41wpA+iLzAPQ0QCwLFg4HQSJwgTgNME41r3NuD/6F/tKDwdEdjJj3+CQ3lsEYyUCz0C6t50GxPfgXeEwc/sN7ggf5Q0DI8l96+K90/i9e5eQ/k/sCMMQgzgdoxkaEzDQAo4Af+A46d4QiQ41tFw6B8EpuNIMxkoBGoVVav0MBvCX6TBj+zxRLgOFJcvhP1v8DeJo2ea8XuRxIlgUDsSgI2UcMQRCJxNUA4wLLl+zbA391bg8iYg0pju2BiK3bhw05nxv3uhmMEQM0CW1Co7RuhwJ4Ct4Ss//wHLwnrgCQxT+ALP9VtPxHX+S+AECeDyAeFIoDCLRabQeOJBKnAcD6iHevfVsgMpxYd/oixt3uzw17GYzCAQ1Ci7Q+hxp4SvQXvCZ4rkM8BIQ8AJTc/w/6qv/PdWWVBev1+npqFGATDgdpRSZSmI/wX1AfNK62Pef7N/uL/shwY9vui5h3eT837pE+HAZjOIDWoDloj9bjcAAvwVMZf+n1CwTPtcKD5OEfAF6lhv+9l//musjVAGwoIJOBiDji4SDCvoCsUYD5q/aH7S8GIvnEuiMdDAx7XJKHxmAMij0u3vTQGK274QZeont/eE48BITs/eFRcvNPv7L/Mtfo3kYBWHYQvkQHIhKqkogotcK2wfdL+1YcXJh/rC96IpYdXpyw8rlhtzMdFBgMpex2fg7tQEPQEq2vfAEPkZ6Cx+A1eA7eo5f+ZHr/0bSp+3WRx4TRW4QReZCEEJYipiMrie2JmS97pfE225bAn+3P+yMFZWsgYn3RF7Fs80TMO9x4qcTnxpfSUZ3BgBagCWgDGoFWoBmJjvIMvAMPEb3/VcLxX9PhOSEJn+n9Adn793r8Vz+urFEAuSQoRBz+bUEGg6FLGAXMJSOW5WvuR234MSOZrf6Idas3Yn0BIwdGSYNnvNXLP3OJDkYY8A7V+88VPNYlHMvnIb0os/Q3uN5fvHobBQiFQagHaBfKEsEi8otbH/Ees21BRGMwGEqAZ0gPwVOEv9oFz2UKf4ar9+cvekmQzAWg+IB4bfg04QtimMKXB/ORy+lZZdno/r31OV+EwWD0DrwCzxABAGW/KLhD5p8/ABSeIwt/6Ln/QJf+cl7kKACQdQHC/oCwmAyUSwgal1m/Yn3G/2frZk+EwWDk4Bn/n+EVaujPJ/7E5B+8Rib/6HX/Ie39iSsrF0BWB+IEEuLNweIoQDIVMK23/4P5Gfd/WzZ7IgwGIxt4Ax7JNfQXe3/Ba5lTf8iqPzBkc3/6IusCALlVGLXIGJaQowB6KsCPBO6yPWzZ7PvcshkvN2QwGGl8n8MbpFfIob/Y+wvr/pn3/pFbfsFg1/37usrJswLI4iBxf4Dw7sDMKECr1c6hftQK09ddT1me8UYYDEYaeIL2CbxD9v5i2a9Y908X/Qh7/vu36ae/F71VWJwKiPsDhG2JbcQoAPmAefSPM95v32p+2hthMNQOvED7A54hPQRPif4S1/7poX9/t/wO+KITguKqgHhYCOYoYl0AQWbLcCYI3Gv/sWmT63PjJgfHYKgNXvv32n9M+4I46UfsQLHuD09lDv2gs/7DlfjLdWWdFyB8gSbyFWLCRiEyIYgqwcxegUyku936PeNG538bNto5BkMt8Jq/3fo92g/wCDnvh4fIl37AY+TLPkWGfehPX3RtgJgPoE8OFkqEew0CxhttDxg2OP5seMrBMRglzwbHn6F52gcy5p9On/hLz/vBkK/5K70sFstY8ovgCGL6BSLiduG+goBuqfEe/Y/sH+uftHMMRsnyI/vHvNb7ML8QALLO+4e3yGO+ATxI+zKfVxmdD0BighwFYO5CLQ2CWXJBwOD0X2f4tuO0foOdYzBKDWgbGqd1L5h/FukRYbcfP+8Xe3866SfM+we2138Ir6ylQYBNCWTkEusDyOkA9jTThUIZ7rY9oXvc+hfdE1aOwSh6Hrf+BZqW6Fwo9BG8kBn2i+v9pIfojT55WfLrx5X1MhFAv0pMo9EEsImBygkg6mF1YBl9Y/SLTV/Rfdf+pu5xG8dgFC3ftb8JLUv0rdcvE7L9mZ5f8EY7vEJ6B16i/aX4JR95vLJKhZGooPMBSGjIBAFUCy40GAxLZG7SCu1dlse037f8u/YxK8dgFA3Q7F2Wx2g9A0HrC+mEH7xBJv0APEQn/Yat1HewF70ygBcT4geIx4gL55eHUdRALxEK55zJTgl0Id0NmgfMxzU/NH+u+ZGFYzBGLNDoA+bj0CytY17LaY1D61lLfUKhT1g84x+eEbyTebknKFjGX+lFVwqK9QF0EBAynGSxEM44R/XTleIR4zTaKwxf0TxgOqP5vvX/Nv3AxDEYIwVoEtqERmndAmha0DY0njG/UOQDL2SZX269P2+VfoO9yJEAhi/YrigcHyYGAWQ3m8XzBGWSg1cIkTJrI1Emis4y3dp0v+mI5lHrX5q+b+YYjELBa/B+0xFoktapADb0YEffFXLJPuE0LXiBz/jDI/AKPEMO/Ud8zy9zZXIC4n4BJDOocmE+COSYEmCOhJuWOWOQRtuhv0nzNcsLTd8xf9z4qJljMPIFNAftQYO0LjP6TJ/hh3dn0vN9fshPmx/eEA/5IJf8RuycX8FVIS4RYi5DbGHkXzMu/HAMfbDHGaOBTmI0gCkBzkDDaKDXQAB0y81fa7zPcLjhIcN/NDxi5BiMIechw39AY9AarT854wNBw+JpPuj1oXFe74L2efOTr/UW5/3CUt+Iy/b39yoXi4XI8wPEvACRE+BvSo7cAE5EURYIjJaVmlWGv2/8mqG7/kH9Ww3fNf61/mEDx2D0F147D+rfgpagKWiL1lsvxodmJXN9yvxucb5P7+8XinxGzDr/YK8y8TARJDbEH4vhDt5qItwI7BsQgwCmBTj4cCqZGxCnBUIgWJwrWZj1UMy2a5vWGL7V+Lf6HY1/b3y14UHjhfrvGP6r7rt6jsEQgSagDWgEWoFmoB1aTzTQoFDJx+sSGiXn+oKGsfSd0bagdTe0T57rJyb9hEM9Cl7hN+SXmBwkg4A4GjCZTA4UQJA3SkkgIEYF0mKiXtC26m/UXGP4RuNN+ocabzU81nCn/scN9xi21n9Nt6vh64YDjNKDf7b3GLY23ml4Gs8czx4agBZoffTBMrK3V2p8AI1D62SvT5q/GJN9/b340mHyUFFi+GMhk4NUIMA6KYZRfI5ACARYT808BCyzECMD2RUEBmMALCd6elTvkcZfIBof2hSmr3yCj0RM9pFzfRF4YaSV9g77hV1M9EgAiNMCekpAgBciIpEirhrMEtZWyUBAB4QlLCgwFMKbHZqRM7yIoDm+jFfYsw9NZub4JNAyPdwne/5C7+gr5FVBv2+QDARCgkQyGhBBpMU70sVgILw0MZMw7AU8VKzNYiMGXrYIrhICBaPEwbMWn7uog1xGp0w/n+jtp0F7cr29CLQLDcsZH0D7pZDlH/QlLHlk3jxMgqKIXNMCCowMcGY6P00QggFeU0ZPExgMRUA70JAw3eSH90LxjmxPTxofmqXf2ycCrQvr++wSL6fTWYX1z1yBQDxuTDh1WHLTZcBBJO0YmgkJGRxEwgcF4aUlWYlEhnoRNqPNF80uLD3jlfedQiKvV8OLiKf20gk+0vjQOLRO659d6Ws0kiFms3myXJJQDASomBLOR8+VJ+gNPEwEB5xczAcIIUh0CUxllDT8cxafu/BOSwzjeV3I6KVXoEFoUahwlTW+oOXJQqKvaKv68nWV63S6GgyRcNPkEoVkIBArCnFw4gADAoOhGMHwOPA2U76by/iCdidDy9C0qrL8g70wTBJrobEpAkMnuVGB8HJSi7C2Sh5DhlOI/MKwLKwgh8Bg8EAr0Ay0Aw0JL7/NHM8FrQmakyT3hI1vdeRGHjbkH/iVGQ2ICAeP1ssFAyRd8NYUMhjQoAJLAO9X8+h0Oi9DvYg6EHVB64U0PbQll9iDFqFJ+sBO1usP0YXqKPrcQXFkgCEWzkujAwKiM96fLqy/5gwIDIYcguFt0BDd00Nr0By0R5/WA6BVNVT05fsqI6cFuUAUxoNBRMbGCqHKSiucUWgUgoJV2HrpEM8oYKgPYY3eAS1AE9CGUJauF95xoYGGhFqVyXQPL4cw3C+9Ov4RdPGBQG5EoAREbICHSYL918K5BZMZpYv4nOnnL+qC1osSoEVm/PxfZTgiaaCBgMEYLNCecEwXM36Br9Gop2bBgDHcQGNC7T5bzx+BVxmSL9hPzYIBY6iAlqApIbHHevsiusoxRGMBgdEfRMMLw3u2jFdCF6J3BSK5sPegGmu1OH4J4MGzQFG6iM9XfN549tAAtCD07tiZp6oe/v8DoBS4ByJdDB4AAAAASUVORK5CYII='

############################################################################
# Build the window
############################################################################
# Windows can be set to open menus right-aligned ("left-handed"), which pushes the leftmost
# menus off-screen. Force left-aligned drop-downs (WPF caches the setting in a private field).
try {
    $script:menuAlignField = [Windows.SystemParameters].GetField('_menuDropAlignment', [Reflection.BindingFlags]'NonPublic,Static')
    $script:fixMenuAlign = { if ($script:menuAlignField -and [Windows.SystemParameters]::MenuDropAlignment) { $script:menuAlignField.SetValue($null, $false) } }
    & $script:fixMenuAlign
    [Windows.SystemParameters]::add_StaticPropertyChanged([ComponentModel.PropertyChangedEventHandler]{ param($s, $e) & $script:fixMenuAlign })
}
catch { }

$xamlText = $script:windowXaml.Replace('@@STYLES@@', $script:stylesXaml).Replace('@@BODY@@', $script:mainBody)
$window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$xamlText)))
foreach ($m in [regex]::Matches($script:mainBody, 'x:Name="(\w+)"')) {
    $n = $m.Groups[1].Value
    $ui[$n] = $window.FindName($n)
}

# Application icon (embedded, green Wireshark fin) - window/taskbar icon and title bar logo
$bmp = New-Object Windows.Media.Imaging.BitmapImage
$bmp.BeginInit()
$bmp.StreamSource = New-Object IO.MemoryStream (, [Convert]::FromBase64String($script:iconB64))
$bmp.CacheOption = [Windows.Media.Imaging.BitmapCacheOption]::OnLoad
$bmp.EndInit()
$bmp.Freeze()
$script:appIcon = $bmp
$window.Icon = $bmp
$ui.imgLogo.Source = $bmp

# Runspace pool for all background work
$script:pool = [runspacefactory]::CreateRunspacePool(1, 6)
$script:pool.ApartmentState = 'MTA'
$script:pool.Open()
[void](Start-Worker $script:adapterWorker @($script:adapters))

$ui.dgPackets.ItemsSource = $script:store

############################################################################
# Events
############################################################################
$copySummary = {
    $p = $ui.dgPackets.SelectedItem
    if ($null -ne $p) { try { [Windows.Clipboard]::SetText((@($p.No, $p.Time, $p.Source, $p.Destination, $p.Protocol, $p.Length, $p.Info) -join "`t")) } catch {} }
}
$resizeCols = {
    foreach ($i in 0..5) { $ui.dgPackets.Columns[$i].Width = [Windows.Controls.DataGridLength]::SizeToCells }
    $ui.dgPackets.UpdateLayout()
}
$toggleCapture = {
    if ($null -ne $script:capState -and -not $script:capState.Done -and -not $script:capState.Cancel) { Stop-Capture } else { Start-Capture }
}

$actions = [ordered]@{
    btMin         = { $window.WindowState = 'Minimized' }
    btMax         = { $window.WindowState = if ($window.WindowState -eq 'Maximized') { 'Normal' } else { 'Maximized' } }
    btExit        = { $window.Close() }
    miQuit        = { $window.Close() }
    miOpen        = { Open-CaptureDialog }
    tbOpen        = { Open-CaptureDialog }
    miSave        = { Save-Capture }
    tbSave        = { Save-Capture }
    miSaveAs      = { Save-CaptureAs }
    miClose       = { Close-Capture }
    tbClose       = { Close-Capture }
    miCopy        = $copySummary
    miFind        = { Show-FindDialog }
    tbFind        = { Show-FindDialog }
    miFindNext    = { Find-Packet $true }
    miFindPrev    = { Find-Packet $false }
    miShowDetails = { Update-Panes }
    miShowBytes   = { $ui.tgBytes.IsChecked = $ui.miShowBytes.IsChecked; Update-Panes }
    tgBytes       = { $ui.miShowBytes.IsChecked = $ui.tgBytes.IsChecked; Update-Panes }
    miZoomIn      = { Set-Zoom ($script:zoom + 1) }
    tbZoomIn      = { Set-Zoom ($script:zoom + 1) }
    miZoomOut     = { Set-Zoom ($script:zoom - 1) }
    tbZoomOut     = { Set-Zoom ($script:zoom - 1) }
    miZoomReset   = { Set-Zoom $script:defaultZoom }
    tbZoomReset   = { Set-Zoom $script:defaultZoom }
    miResizeCols  = $resizeCols
    tbResizeCols  = $resizeCols
    miExpandAll   = { Set-TreeExpanded $true }
    miCollapseAll = { Set-TreeExpanded $false }
    miAutoScroll  = { Set-AutoScroll ([bool]$ui.miAutoScroll.IsChecked) }
    tgAutoScroll  = { Set-AutoScroll ([bool]$ui.tgAutoScroll.IsChecked) }
    miColorize    = { Set-Colorize ([bool]$ui.miColorize.IsChecked) }
    tgColorize    = { Set-Colorize ([bool]$ui.tgColorize.IsChecked) }
    miGoTo        = { Show-GoToDialog }
    tbGoTo        = { Show-GoToDialog }
    miPrev        = { Select-PacketIndex ($ui.dgPackets.SelectedIndex - 1) }
    tbPrev        = { Select-PacketIndex ($ui.dgPackets.SelectedIndex - 1) }
    miNext        = { Select-PacketIndex ($ui.dgPackets.SelectedIndex + 1) }
    tbNext        = { Select-PacketIndex ($ui.dgPackets.SelectedIndex + 1) }
    miFirst       = { Select-PacketIndex 0 }
    tbFirst       = { Select-PacketIndex 0 }
    miLast        = { Select-PacketIndex ($script:store.Count - 1) }
    tbLast        = { Select-PacketIndex ($script:store.Count - 1) }
    miCapOptions  = { if (Show-CaptureOptions) { Start-Capture } }
    tbOptions     = { if (Show-CaptureOptions) { Start-Capture } }
    miCapStart    = { Start-Capture }
    tbStart       = { Start-Capture }
    miCapStop     = { Stop-Capture }
    tbStop        = { Stop-Capture }
    miCapRestart  = { Restart-Capture }
    tbRestart     = { Restart-Capture }
    miAbout       = { Show-AboutDialog }
    btApply       = { Invoke-DisplayFilter }
    btClear       = { $ui.tbFilter.Text = ''; Invoke-DisplayFilter }
}
foreach ($k in $actions.Keys) { $ui[$k].Add_Click($actions[$k]) }

$ui.tbFilter.Add_TextChanged({ Set-FilterColor $ui.tbFilter })
$ui.tbFilter.Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { $e.Handled = $true; Invoke-DisplayFilter } })
$ui.dgPackets.Add_SelectionChanged({ Show-Packet })
$ui.tvDetail.Add_PreviewMouseRightButtonDown({
    param($s, $e)
    $tvi = Find-TreeItemAt $e.OriginalSource
    if ($null -ne $tvi) { $tvi.IsSelected = $true }
})
$ui.tvDetail.Add_ContextMenuOpening({
    param($s, $e)
    $tvi = Find-TreeItemAt $e.OriginalSource
    $node = if ($null -ne $tvi) { $tvi.DataContext } else { $ui.tvDetail.SelectedItem }
    $count = 0
    if ($null -ne $node) { $count = Set-DetailMenu $node.Text }
    if ($count -eq 0) { $e.Handled = $true }        # nothing to copy on this line: no menu
})
$ui.tvDetail.Add_SelectedItemChanged({
    $n = $ui.tvDetail.SelectedItem
    $p = $ui.dgPackets.SelectedItem
    if ($null -ne $n -and $null -ne $p) { Set-Hex $p.Data $n.Start $n.Length }
})

$window.Add_StateChanged({
    if ($window.WindowState -eq 'Maximized') { $ui.rootBorder.Margin = [Windows.SystemParameters]::WindowResizeBorderThickness; $ui.btMax.Content = [string][char]0x2750 }
    else { $ui.rootBorder.Margin = New-Object Windows.Thickness(0); $ui.btMax.Content = [string][char]0x25A1 }
})

# Drag & drop a capture file onto the window
$window.Add_DragOver({ param($s, $e) if ($e.Data.GetDataPresent([Windows.DataFormats]::FileDrop)) { $e.Effects = [Windows.DragDropEffects]::Copy } else { $e.Effects = [Windows.DragDropEffects]::None }; $e.Handled = $true })
$window.Add_Drop({
    param($s, $e)
    $f = $e.Data.GetData([Windows.DataFormats]::FileDrop)
    if ($f -and $f.Length -gt 0) { Open-CaptureFile $f[0] }
})

# Keyboard shortcuts (same as Wireshark where they exist)
$window.Add_PreviewKeyDown({
    param($s, $e)
    $mod = [Windows.Input.Keyboard]::Modifiers
    $ctrl = ($mod -band [Windows.Input.ModifierKeys]::Control) -ne 0
    $shift = ($mod -band [Windows.Input.ModifierKeys]::Shift) -ne 0
    $key = if ($e.Key -eq 'System') { $e.SystemKey.ToString() } else { $e.Key.ToString() }
    if (-not $ctrl) {
        if ($key -eq 'F3') { Find-Packet (-not $shift); $e.Handled = $true }
        return
    }
    $inText = $e.OriginalSource -is [Windows.Controls.TextBox]
    if ($inText -and ($key -in 'Left', 'Right', 'Home', 'End', 'Up', 'Down', 'C', 'X', 'V', 'A', 'Z', 'Y')) { return }
    $handled = $true
    switch ($key) {
        'O' { Open-CaptureDialog }
        'S' { if ($shift) { Save-CaptureAs } else { Save-Capture } }
        'W' { Close-Capture }
        'Q' { $window.Close() }
        'F' { Show-FindDialog }
        'N' { Find-Packet $true }
        'B' { Find-Packet $false }
        'G' { Show-GoToDialog }
        'E' { & $toggleCapture }
        'R' { if ($shift) { & $resizeCols } else { Restart-Capture } }
        'K' { if (-not (Test-Busy)) { if (Show-CaptureOptions) { Start-Capture } } }
        'C' { if ($shift) { & $copySummary } else { $handled = $false } }
        'Up' { Select-PacketIndex ($ui.dgPackets.SelectedIndex - 1) }
        'Down' { Select-PacketIndex ($ui.dgPackets.SelectedIndex + 1) }
        'Home' { Select-PacketIndex 0 }
        'End' { Select-PacketIndex ($script:store.Count - 1) }
        'OemPlus' { Set-Zoom ($script:zoom + 1) }
        'Add' { Set-Zoom ($script:zoom + 1) }
        'OemMinus' { Set-Zoom ($script:zoom - 1) }
        'Subtract' { Set-Zoom ($script:zoom - 1) }
        'D0' { Set-Zoom $script:defaultZoom }
        'NumPad0' { Set-Zoom $script:defaultZoom }
        'Right' { Set-TreeExpanded $true }
        'Left' { Set-TreeExpanded $false }
        'OemQuestion' { [void]$ui.tbFilter.Focus() }
        default { $handled = $false }
    }
    if ($handled) { $e.Handled = $true }
})

# Closing: make sure the ETW/NetEvent capture session is really stopped
$window.Add_Closing({
    param($s, $e)
    if (-not (Confirm-Discard 'exit')) { $e.Cancel = $true; return }
    foreach ($st in @($script:readState, $script:parseState, $script:writeState)) { if ($null -ne $st) { $st.Cancel = $true } }
    if ($null -ne $script:capState -and -not $script:capState.Done) {
        $ui.tbStatusMsg.Text = 'Stopping capture ...'
        Stop-Capture
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while (-not $script:capState.Done -and $sw.ElapsedMilliseconds -lt 10000) {
            Start-Sleep -Milliseconds 100
            $window.Dispatcher.Invoke([Action]{}, [Windows.Threading.DispatcherPriority]::Background)
        }
    }
})
$window.Add_Closed({
    $script:timer.Stop()
    try { $script:pool.Close(); $script:pool.Dispose() } catch {}
})

############################################################################
# Start-up
############################################################################
Update-Panes
Set-Zoom $script:defaultZoom
Update-Title
Update-Controls
Update-Status

$script:timer = New-Object Windows.Threading.DispatcherTimer
$script:timer.Interval = [TimeSpan]::FromMilliseconds(100)
$script:timer.Add_Tick({ Invoke-Tick })
$script:timer.Start()

$window.Add_ContentRendered({
    if ($script:started) { return }
    $script:started = $true
    if (-not $script:isAdmin -and -not $Screenshot) {
        $choice = Show-AdminNotice
        if ($choice -eq 'exit') { $window.Close(); return }
        if ($choice -eq 'elevate') { Restart-Elevated; return }
    }
    if ($OpenFile) {
        try { Open-CaptureFile (Resolve-Path -LiteralPath $OpenFile).ProviderPath }
        catch { [void][Windows.MessageBox]::Show($window, "Cannot open '$OpenFile'.", 'PSShark', 'OK', 'Error') }
    }
    if ($Screenshot) {
        $script:shotTimer = New-Object Windows.Threading.DispatcherTimer
        $script:shotTimer.Interval = [TimeSpan]::FromMilliseconds(300)
        $script:shotTimer.Add_Tick({
            $ready = ($null -ne $script:readState) -and $script:readState.Done -and $script:parseState.Done -and $script:uiQ.IsEmpty
            if (-not $ready -and $script:shotWait -lt 100) { $script:shotWait++; return }
            $script:shotTimer.Stop()
            if ($DisplayFilter) { $ui.tbFilter.Text = $DisplayFilter; Invoke-DisplayFilter }
            if ($SelectPacket -gt 0) { $i = $script:store.IndexOfNo($SelectPacket); if ($i -ge 0) { Select-PacketIndex $i } }
            $window.Dispatcher.Invoke([Action]{}, [Windows.Threading.DispatcherPriority]::Background)
            if ($ui.tvDetail.Items.Count -gt 0) { Set-TreeExpanded $true }
            $window.Dispatcher.Invoke([Action]{}, [Windows.Threading.DispatcherPriority]::ApplicationIdle)
            Save-Screenshot $Screenshot
            $script:dirty = $false
            $window.Close()
        })
        $script:shotTimer.Start()
    }
})
$script:started = $false
$script:shotWait = 0

if (-not $env:PSSHARK_NORUN) { [void]$window.ShowDialog() }   # PSSHARK_NORUN: lets a test harness dot-source and drive the app