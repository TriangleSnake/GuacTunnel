#Requires -Version 5.1
<#
.SYNOPSIS
    GuacTunnel - Target-side agent (PowerShell)
.DESCRIPTION
    Polls clipboard for GT: tunnel frames, forwards TCP connections to internal
    hosts, and writes responses back to clipboard — turning Guacamole CLIPRDR
    into a bidirectional SOCKS5-capable data channel.
.EXAMPLE
    .\agent.ps1
    .\agent.ps1 -PollMs 150 -Debug
#>
param(
    [int]    $PollMs   = 150,    # clipboard poll interval (ms)
    [int]    $MaxChunk = 800,    # max payload bytes per frame
    [int]    $IdleTimeoutSec = 120, # close channels with no client activity
    [switch] $ClearClipboard,
    [switch] $Debug
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ─── Tunnel protocol ──────────────────────────────────────────────────────────

$MAGIC       = "GT"
$SEQ_WINDOW  = 64
$script:seenSeqs = [System.Collections.Generic.Queue[int]]::new()

function New-Frame {
    param([int]$Seq, [int]$Chan, [string]$Ctrl, [byte[]]$Payload = @())
    $b64 = if ($Payload.Count -gt 0) { [Convert]::ToBase64String($Payload) } else { "" }
    return "${MAGIC}:${Seq}:${Chan}:${Ctrl}:${b64}"
}

function Parse-Frame {
    param([string]$Text)
    if (-not $Text.StartsWith("${MAGIC}:")) { return $null }
    $parts = $Text -split ":", 5
    if ($parts.Count -ne 5) { return $null }
    try {
        $seq     = [int]$parts[1]
        $chan    = [int]$parts[2]
        $ctrl    = $parts[3]
        $payload = if ($parts[4] -ne "") { [Convert]::FromBase64String($parts[4]) } else { @() }
        return @{ Seq = $seq; Chan = $chan; Ctrl = $ctrl; Payload = $payload }
    } catch { return $null }
}

function Test-NewSeq {
    param([int]$Seq)
    if ($script:seenSeqs -contains $Seq) { return $false }
    $script:seenSeqs.Enqueue($Seq)
    if ($script:seenSeqs.Count -gt $SEQ_WINDOW) { $script:seenSeqs.Dequeue() | Out-Null }
    return $true
}

# ─── Clipboard I/O ───────────────────────────────────────────────────────────

Add-Type -AssemblyName System.Windows.Forms

if (-not ("GuacTunnel.SeqCounter" -as [type])) {
    Add-Type -ReferencedAssemblies System.Windows.Forms -TypeDefinition @"
using System;
using System.Threading;
using System.Windows.Forms;

namespace GuacTunnel {
    public sealed class SeqCounter {
        private int value;
        public SeqCounter() : this(0) {}
        public SeqCounter(int initialValue) {
            value = initialValue;
        }
        public int Next() {
            return System.Threading.Interlocked.Increment(ref value);
        }
    }

    public sealed class BoolBox {
        public volatile bool Value;
    }

    public static class ClipboardIo {
        public static string GetText() {
            string result = "";
            Exception error = null;
            Thread thread = new Thread(() => {
                try {
                    result = Clipboard.GetText();
                } catch (Exception ex) {
                    error = ex;
                }
            });
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            thread.Join();
            if (error != null) {
                throw error;
            }
            return result ?? "";
        }

        public static void SetText(string text) {
            Exception error = null;
            Thread thread = new Thread(() => {
                try {
                    Clipboard.SetText(text ?? "");
                } catch (Exception ex) {
                    error = ex;
                }
            });
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            thread.Join();
            if (error != null) {
                throw error;
            }
        }
    }
}
"@
}

function Get-ClipboardText {
    try {
        # Use STA thread to access clipboard
        $result = $null
        $ps = [PowerShell]::Create()
        $ps.AddScript({
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.Clipboard]::GetText()
        }) | Out-Null
        $result = $ps.Invoke()
        $ps.Dispose()
        return ($result | Select-Object -First 1)
    } catch {
        return ""
    }
}

function Set-ClipboardText {
    param([string]$Text)
    try {
        $ps = [PowerShell]::Create()
        $ps.AddScript({
            param($t)
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.Clipboard]::SetText($t)
        }).AddArgument($Text) | Out-Null
        $ps.Invoke()
        $ps.Dispose()
    } catch {}
}

# Clipboard helpers are STA-safe even when powershell.exe was started as MTA.
function Read-Clip { [GuacTunnel.ClipboardIo]::GetText() }
function Write-Clip { param([string]$s) [GuacTunnel.ClipboardIo]::SetText($s) }

# ─── Channel table ────────────────────────────────────────────────────────────

$script:channels  = @{}   # chan_id → @{Client; Stream; ClosedRef; Reader}
$script:outbox    = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
$script:sendSeq   = [GuacTunnel.SeqCounter]::new((Get-Random -Minimum 1 -Maximum 1000000000))

function Enqueue-Frame {
    param([int]$Chan, [string]$Ctrl, [byte[]]$Payload = @(), [int]$Repeat = 1)
    $seq = $script:sendSeq.Next()
    $frame = New-Frame -Seq $seq -Chan $Chan -Ctrl $Ctrl -Payload $Payload
    for ($i = 0; $i -lt [Math]::Max(1, $Repeat); $i++) {
        $script:outbox.Enqueue($frame) | Out-Null
    }
    if ($Debug) { Write-Host "[DBG] TX  $frame" }
}

# ─── Per-channel TCP reader (runs in thread job) ─────────────────────────────

function Start-ChannelReader {
    param([int]$ChanId, [System.Net.Sockets.NetworkStream]$Stream,
          [System.Collections.Concurrent.ConcurrentQueue[string]]$Outbox,
          [GuacTunnel.SeqCounter]$SeqCounter, [GuacTunnel.BoolBox]$ClosedRef,
          [int]$ChunkSize, [bool]$DebugEnabled)

    $rs = [RunspaceFactory]::CreateRunspace()
    $rs.Open()
    $rs.SessionStateProxy.SetVariable("ChanId",    $ChanId)
    $rs.SessionStateProxy.SetVariable("Stream",    $Stream)
    $rs.SessionStateProxy.SetVariable("Outbox",    $Outbox)
    $rs.SessionStateProxy.SetVariable("SeqCounter", $SeqCounter)
    $rs.SessionStateProxy.SetVariable("ClosedRef", $ClosedRef)
    $rs.SessionStateProxy.SetVariable("ChunkSize", $ChunkSize)
    $rs.SessionStateProxy.SetVariable("MAGIC",     "GT")
    $rs.SessionStateProxy.SetVariable("DebugEnabled", $DebugEnabled)

    $ps = [PowerShell]::Create()
    $ps.Runspace = $rs
    $ps.AddScript({
        $buf = New-Object byte[] $ChunkSize
        try {
            while (-not $ClosedRef.Value) {
                $n = $Stream.Read($buf, 0, $buf.Length)
                if ($n -le 0) { break }
                $chunk = $buf[0..($n-1)]
                $seq = $SeqCounter.Next()
                $b64 = [Convert]::ToBase64String($chunk)
                $frame = "${MAGIC}:${seq}:${ChanId}:DATA:${b64}"
                for ($i = 0; $i -lt 3; $i++) {
                    $Outbox.Enqueue($frame)
                }
                if ($DebugEnabled) {
                    [Console]::WriteLine("[DBG] TCP RX channel {0}: {1} bytes" -f $ChanId, $n)
                }
            }
        } catch {
            if ($DebugEnabled) {
                [Console]::WriteLine("[DBG] TCP reader channel {0} error: {1}" -f $ChanId, $_)
            }
        }
        # send CLOSE
        $seq = $SeqCounter.Next()
        $frame = "${MAGIC}:${seq}:${ChanId}:CLOSE:"
        $Outbox.Enqueue($frame)
        if ($DebugEnabled) {
            [Console]::WriteLine("[DBG] TCP reader channel {0} closed" -f $ChanId)
        }
        $ClosedRef.Value = $true
    }) | Out-Null

    $handle = $ps.BeginInvoke()
    return @{ PS = $ps; RS = $rs; Handle = $handle }
}

# ─── Channel lifecycle ────────────────────────────────────────────────────────

function Open-Channel {
    param([int]$ChanId, [string]$RemoteHost, [int]$Port)

    try {
        $existing = $script:channels[$ChanId]
        if ($existing) {
            if ($existing.RemoteHost -eq $RemoteHost -and $existing.Port -eq $Port -and -not $existing.ClosedRef.Value) {
                if ($Debug) { Write-Host "[DBG] Channel $ChanId already open → ${RemoteHost}:${Port}; re-sending CONNECTED" }
                $existing.LastActivity = [datetime]::UtcNow
                Enqueue-Frame -Chan $ChanId -Ctrl "CONNECTED"
                return
            } else {
                if ($Debug) { Write-Host "[DBG] Channel $ChanId already exists; closing stale channel before reconnect" }
                Close-Channel -ChanId $ChanId
            }
        }

        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect($RemoteHost, $Port)
        $stream = $client.GetStream()
        $closed = [GuacTunnel.BoolBox]::new()
        $closed.Value = $false

        $ch = @{
            Client  = $client
            Stream  = $stream
            ClosedRef = $closed
            RemoteHost = $RemoteHost
            Port = $Port
            ReaderStarted = $false
            LastActivity = [datetime]::UtcNow
        }
        $script:channels[$ChanId] = $ch

        Enqueue-Frame -Chan $ChanId -Ctrl "CONNECTED"

        if ($Debug) { Write-Host "[DBG] Channel $ChanId opened → ${RemoteHost}:${Port}" }
    } catch {
        if ($Debug) { Write-Host "[DBG] Channel $ChanId connect failed: $_" }
        Enqueue-Frame -Chan $ChanId -Ctrl "CLOSE"
    }
}

function Close-Channel {
    param([int]$ChanId)
    $ch = $script:channels[$ChanId]
    if (-not $ch) { return }
    $ch.ClosedRef.Value = $true
    try { $ch.Stream.Close() } catch {}
    try { $ch.Client.Close() } catch {}
    $script:channels.Remove($ChanId)
    if ($Debug) { Write-Host "[DBG] Channel $ChanId closed" }
}

function Send-DataToChannel {
    param([int]$ChanId, [byte[]]$Data)
    $ch = $script:channels[$ChanId]
    if (-not $ch -or $ch.ClosedRef.Value) { return }
    try {
        $ch.LastActivity = [datetime]::UtcNow
        $ch.Stream.Write($Data, 0, $Data.Length)
        $ch.Stream.Flush()
        if ($Debug) { Write-Host "[DBG] TCP TX channel ${ChanId}: $($Data.Length) bytes" }

        if (-not $ch.ReaderStarted) {
            $ch.ReaderStarted = $true
            $ch.Reader = Start-ChannelReader `
                -ChanId   $ChanId `
                -Stream   $ch.Stream `
                -Outbox   $script:outbox `
                -SeqCounter $script:sendSeq `
                -ClosedRef  $ch.ClosedRef `
                -ChunkSize  $MaxChunk `
                -DebugEnabled ([bool]$Debug)
        }
    } catch {
        if ($Debug) { Write-Host "[DBG] TCP TX channel ${ChanId} error: $_" }
        Close-Channel -ChanId $ChanId
    }
}

function Cleanup-StaleChannels {
    $now = [datetime]::UtcNow
    foreach ($chanId in @($script:channels.Keys)) {
        $ch = $script:channels[$chanId]
        if (-not $ch) { continue }

        $idle = ($now - $ch.LastActivity).TotalSeconds
        if ($ch.ClosedRef.Value -or $idle -ge $IdleTimeoutSec) {
            if ($Debug -and -not $ch.ClosedRef.Value) {
                Write-Host "[DBG] Channel $chanId idle timeout (${IdleTimeoutSec}s); closing"
            }
            Close-Channel -ChanId $chanId
        }
    }
}

# ─── Main loop ────────────────────────────────────────────────────────────────

Write-Host "GuacTunnel agent started (poll=${PollMs}ms)"
Write-Host "Waiting for operator connection…"

$lastClip    = ""
$lastTxFrame = ""

if ($ClearClipboard) {
    try {
        Write-Clip -s ""
        $lastClip = ""
        $lastTxFrame = ""
        if ($Debug) { Write-Host "[DBG] Clipboard cleared" }
    } catch {
        if ($Debug) { Write-Host "[DBG] Clipboard clear error: $_" }
    }
}

while ($true) {
    # ── RX: check clipboard for incoming frames ──
    try {
        $clip = Read-Clip
        if ($clip -ne $lastClip -and $clip.StartsWith("${MAGIC}:")) {
            $lastClip = $clip
            if ($clip -ne $lastTxFrame) {
                $f = Parse-Frame -Text $clip
                if ($f -and (Test-NewSeq -Seq $f.Seq)) {
                    if ($Debug) { Write-Host "[DBG] RX  $clip" }
                    switch ($f.Ctrl) {
                        "CONNECT" {
                            $addr = [System.Text.Encoding]::UTF8.GetString($f.Payload)
                            $parts = $addr -split ":"
                            if ($parts.Count -ge 2) {
                                $h = $parts[0]; $p = [int]$parts[1]
                                Open-Channel -ChanId $f.Chan -RemoteHost $h -Port $p
                            }
                        }
                        "DATA" {
                            Send-DataToChannel -ChanId $f.Chan -Data $f.Payload
                        }
                        "CLOSE" {
                            Close-Channel -ChanId $f.Chan
                        }
                        "PING" {
                            Enqueue-Frame -Chan $f.Chan -Ctrl "PONG"
                        }
                    }
                }
            }
        }
    } catch {
        if ($Debug) { Write-Host "[DBG] RX error: $_" }
    }

    # ── TX: flush one frame from outbox to clipboard ──
    $frame = $null
    if ($script:outbox.TryDequeue([ref]$frame)) {
        try {
            if ($frame -ne $lastTxFrame) {
                Write-Clip -s $frame
                $lastTxFrame = $frame
            }
        } catch {
            if ($Debug) { Write-Host "[DBG] TX clipboard error: $_" }
            $script:outbox.Enqueue($frame)
        }
    }

    Cleanup-StaleChannels

    Start-Sleep -Milliseconds $PollMs
}
