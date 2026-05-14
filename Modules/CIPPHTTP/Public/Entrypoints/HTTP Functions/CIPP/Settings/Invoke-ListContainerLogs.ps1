function Invoke-ListContainerLogs {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        CIPP.SuperAdmin.Read
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Action = $Request.Query.Action ?? 'ReadLog'

    try {
        switch ($Action) {
            'ListFiles' {
                $Results = [Craft.Services.LogBridge]::GetLogFiles()
                $Body = @{ Results = @($Results) }
            }
            'ReadLog' {
                $Tail = [int]($Request.Query.Tail ?? '500')
                $Level = $Request.Query.Level
                $Search = $Request.Query.Search
                $File = $Request.Query.File

                # Date range parsing
                $From = $null
                $To = $null
                if ($Request.Query.From) {
                    $From = [DateTime]::Parse($Request.Query.From).ToUniversalTime()
                }
                if ($Request.Query.To) {
                    $To = [DateTime]::Parse($Request.Query.To).ToUniversalTime()
                }

                # Resolve nullable params
                $LevelParam = if ([string]::IsNullOrEmpty($Level)) { $null } else { $Level }
                $SearchParam = if ([string]::IsNullOrEmpty($Search)) { $null } else { $Search }
                $FileParam = if ([string]::IsNullOrEmpty($File)) { $null } else { $File }

                $Lines = [Craft.Services.LogBridge]::ReadLog($Tail, $LevelParam, $SearchParam, $FileParam, $From, $To)

                # Parse log lines into structured objects for the table
                $Results = foreach ($Line in $Lines) {
                    if ([string]::IsNullOrWhiteSpace($Line)) { continue }
                    # Continuation lines (exception details) — skip, they were attached to previous
                    if ($Line.Length -gt 0 -and [char]::IsWhiteSpace($Line[0])) { continue }

                    # Parse: "2026-05-13 10:30:00.000 [INF] message text"
                    if ($Line -match '^\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+\[(\w+)\]\s+(.*)$') {
                        [PSCustomObject]@{
                            Timestamp = "$($Matches[1].Replace(' ', 'T'))Z"
                            Level     = $Matches[2]
                            Message   = $Matches[3]
                            Raw       = $Line
                        }
                    } elseif ($Line -match '^\s*(\d{2}:\d{2}:\d{2}\.\d{3})\s+\[(\w+)\]\s+(.*)$') {
                        # Legacy time-only format
                        [PSCustomObject]@{
                            Timestamp = "$($Matches[1])Z"
                            Level     = $Matches[2]
                            Message   = $Matches[3]
                            Raw       = $Line
                        }
                    } else {
                        [PSCustomObject]@{
                            Timestamp = ''
                            Level     = ''
                            Message   = $Line
                            Raw       = $Line
                        }
                    }
                }
                $Body = @{ Results = @($Results) }
            }
            'SearchAll' {
                $Search = $Request.Query.Search
                $Level = $Request.Query.Level
                $Tail = [int]($Request.Query.Tail ?? '500')

                $From = $null
                $To = $null
                if ($Request.Query.From) {
                    $From = [DateTime]::Parse($Request.Query.From).ToUniversalTime()
                }
                if ($Request.Query.To) {
                    $To = [DateTime]::Parse($Request.Query.To).ToUniversalTime()
                }

                $SearchParam = if ([string]::IsNullOrEmpty($Search)) { $null } else { $Search }
                $LevelParam = if ([string]::IsNullOrEmpty($Level)) { $null } else { $Level }

                $Lines = [Craft.Services.LogBridge]::SearchAllFiles($SearchParam, $LevelParam, $From, $To, $Tail)

                $Results = foreach ($Line in $Lines) {
                    if ([string]::IsNullOrWhiteSpace($Line)) { continue }
                    if ($Line.Length -gt 0 -and [char]::IsWhiteSpace($Line[0])) { continue }

                    if ($Line -match '^\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+\[(\w+)\]\s+(.*)$') {
                        [PSCustomObject]@{
                            Timestamp = "$($Matches[1].Replace(' ', 'T'))Z"
                            Level     = $Matches[2]
                            Message   = $Matches[3]
                            Raw       = $Line
                        }
                    } else {
                        [PSCustomObject]@{
                            Timestamp = ''
                            Level     = ''
                            Message   = $Line
                            Raw       = $Line
                        }
                    }
                }
                $Body = @{ Results = @($Results) }
            }
            'GetInfo' {
                $Body = @{
                    Results = @{
                        CurrentFile  = [Craft.Services.LogBridge]::GetCurrentLogPath()
                        LogDirectory = [Craft.Services.LogBridge]::GetLogDirectory()
                        Files        = @([Craft.Services.LogBridge]::GetLogFiles())
                    }
                }
            }
            default {
                $Body = @{ Results = "Unknown action: $Action" }
                return [HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = $Body
                }
            }
        }
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API $APIName -message "Container logs error: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::InternalServerError
            Body       = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" }
        }
    }

    return [HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $Body
    }
}
