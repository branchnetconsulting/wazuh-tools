#!/bin/pwsh
[CmdletBinding(SupportsShouldProcess=$true)]
param (
  [string]$IndexPattern  = "",
  [switch]$IngestTime    = $false,
  [string]$Fields        = "",
  [switch]$CSV           = $false,
  [switch]$JSON          = $false,
  [bool]$SkipHeader      = $false,
  [int]$PageSize         = 5000,
  [int]$MaxRecords       = 100000,
  [string]$StartTime     = "now-1h",
  [string]$EndTime       = "now",
  [switch]$help          = $False,
  [string]$CredsFile     = "",
  [hashtable]$QueryBody  = @{},
  [string]$QueryBodyFile = "",
  [string]$QueryLine     = "",
  [string]$QueryLineFile = ""
)

$FinalResults = @()
$PageCount=0

$TMPDIR=$(mktemp -d -t esquery-XXXXXXXX)
# Confirm temp dir created properly as it will be recursively deleted upon exit.
if ($TMPDIR -notlike "/tmp/esquery*"){
	write-output "Unexpected temp directory generation failure!"
    echo "exit"
}

function bail_out() {
	rm -rf $TMPDIR
    exit;
}

function show_usage() {
   echo @"
Usage syntax:
   esquery -IndexPattern IDX [ -CredsFile CFILE ] [ -QueryBody 'QBODY' ] [ -QueryBodyFile QBFILE ] [ -QueryLine 'QLINE' ] [ -QueryLineFile QLFILE ] [ -StartTime STIME ] [ -EndTime ETIME ] [ -Fields FLIST ] [ -CSV ] [ -SkipHeader] [ -SortList "SLIST" ] [ -PageSize PSIZE ] [ -MaxRecords MRECS ] [ -Debug ]
where
   IDX is one or more comma separated index names or index patterns like:
      *:wazuh-alerts-*
      *:so-ids-*
      indexA,indexB
   CFILE is the filename of dot-callable credentials file that must at least define ESPASS, and generally should define all of ESUSER, ESPASS, ESPROTO, ESHOST, and ESPORT.
   QBODY is the QueryDSL-format search filter to use
      Powershell array object containing query syntax.
      i.e. -QueryBody '\''{ "query_string": { "query": "ssl.server_name: *.org AND NOT destination.geo.country_name: \"United States\"" } }'\''
   QBFILE is the name of a file containing the QueryDSL criteria body to use, like these where the the default is:
      {"match_all":{}}
   and the following is a multiline example QueryDSL body
      {
        "query_string": {
          "query": "ssl.server_name: *.com AND NOT destination.geo.country_name: \"United States\""
        }
      }
   QLINE is the queryline-format search criteria to use
      i.e. -QueryLine '\''ssl.server_name: *.org AND destination.geo.country_name: \"United States\"'\''
   QLFILE is the name of a file containing a queryline-format query, like
      ssl.server_name: *.org AND destination.geo.country_name: "United States"
   STIME is starting absolute or relative time for query - default is now-1h.
      now-14h				(14 hours ago)
      now-10m				(10 minutes ago)
      2022-07-06T16:46:53.084Z		(UTC time)
      2022-07-06T18:00:53.084-0400	(EDT time zone)
   ETIME is ending absolute or relative time for query - default is now.
   FLIST is a CSV list (no spaces) of field names to limit the results to in place of returning all of _source.
      .field1,.fruit.type,.fruit.color,.very.very.deep.field.name
   -CSV causes output to be in CSV format. Default output is powershell native format.
   -JSON causes output to be in JSON format. Default output is powershell native format.
   -SkipHeader skips the output of the CSV header line that is included by default when -Fields is used.
   SLIST is a CSV list (no spaces) of colon-delimited pairs of field name and sort direction (asc or desc) for ordering query results, with a default of:
      @timestamp:asc
   PSIZE is number of records to pull per page of query results, with a default of
      5000
   MRECS is the maximum number of records to actually output to stdout, which also roughly determines the maximum number of pages to pull.  Default is:
      100000
   -Debug enables debug output.\n'
"@
   bail_out
}


if (($IndexPattern -eq "") -Or $help){
	show_usage
}

# Dot-call the credentials file if specified, bark if no such file, confirm ESPASS defined and provide defaults for the rest as needed.
if ($CredsFile -ne ""){
    if (Test-Path $CredsFile){
        $creds = Get-Content $CredsFile|select-string -pattern '([\w]+)\=([\d\w\.]+)'
        ForEach ($cred in $creds){
            New-Variable -Name $cred.matches.groups[1].Value -Value $cred.matches.groups[2].Value -Force
        }
    }else{
        write-output "Missing -CredsFile $CredsFile."
        show_usage
    }
}else{
    if (!$ESPASS -Or $ESPASS -eq ""){
        write-output "Missing or incomplete Elasticsearch credentials. Use -CredsFile to provide a dot-callable script to define ESUSER, ESPASS, ESPROTO, ESHOST, and ESPORT.\n"
        show_usage
    }
    if ($ESUSER -eq ""){
        $ESPROTO=elastic
    }
    if ($ESUSER -eq ""){
        $ESPROTO=https
    }
    if ($ESHOST -eq ""){
        $ESHOST=127.0.0.1
    }
    if ($ESPORT -eq ""){
        $ESPORT = 9200
    }
}

#Setup ElasticSearch Credentials
$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($ESUSER):$($ESPASS)"))
$basicAuthValue = "Basic $encodedCreds"
$Headers = @{
    Authorization = $basicAuthValue
}

# Confirm Elasticsearch can be accessed successfully
$uri = $ESPROTO+"://"+$ESHOST+":"+$ESPORT+"?pretty"
$ESCheckResult = Invoke-WebRequest -SkipCertificateCheck -Uri $uri -Headers $Headers
if (!($ESCheckResult.Content|convertfrom-json).cluster_name){
    write-output "Failed to access Elasticsearch..."
    $ESCheckResult.Content|convertfrom-json
    bail_out
}

# Default to using a match_all QueryBody if no -Query*File setting specified
if ($QueryBodyFile -eq "" -And $QueryLineFile -eq "" -And $QueryBody.Count -eq 0 -And $QueryLine -eq ""){
	$QueryBody= @{
        "match_all" = @{}
    }
}

if ((($QueryBody.Count -ne 0) -Or $QueryBodyFile -ne "") -And ($QueryLine -ne "" -Or $QueryLineFile -ne "")){
    write-output "You can not use -QueryBody/-QueryBodyFile and -QueryLine/-QueryLineFile at the same time."
    show_usage
}

if($QueryBody -ne "" -And $QueryBodyFile -ne ""){
    write-output "You can not use -QueryBody and -QueryBodyFile at the same time."
    show_usage
}

if ($QueryLine -ne "" -And $QueryLineFile -ne ""){
    write-output "You can not use -QueryLine and -QueryLineFile at the same time."
    show_usage
}

if ($QueryLineFile -ne ""){
    if (!Test-Path $QueryLineFile){
        write-output "-QueryLineFile $QueryLineFile not found."
        bail_out
    }
    ###
    copy-item $QueryLineFile $TMPDIR/QueryLine
	# escape any double quotes in the QueryLineFile
	sed -i 's/"/\\"/g' $TMPDIR/QueryLine
	$QueryLine=Get-Content $TMPDIR/QueryLine
    $QueryBody = @{
        "query_string" = @{
            "query" = $QueryLine
        }
    }
}

if ($QueryLine -ne ""){
    $QueryBody = @{
        "query_string" = @{
            "query" = $QueryLine
        }
    }
}

if ($QueryBody -eq ""){
    write-output "QueryBody still empty. Provide QueryLine, QueryLineFile, QueryBody, QueryBodyFile."
    show_usage
}

if ($CSV -And $Fields -eq ""){
    write-output "CSV can only be used in conjunction with -Fields."
    show_usage
}

# Wrap QueryBody into larger body that includes time range filter
$FilterRangeField = If ($IngestTime) {"event.ingest_time"} Else {"@timestamp"}
$QueryBody = @{
    "bool" = @{
        "must" = @(
            $QueryBody
        )
        "filter" = @(
            @{
                "range" = @{
                    $FilterRangeField = @{
                        "gte" = $StartTime
                        "lte" = $EndTime
                    }
                }
            }
        )
    }
}

$SortBody = @(
    @{
        "@timestamp" = "asc"
    }
)

#Format Fields
# if ($Fields -ne ""){
#     $FLIST=""
# }
$FieldsBody = @()
$FieldsBody += "@timestamp"
$FieldsBody += ($Fields  -split ",")

if ($IndexPattern -eq ""){
    write-output "An index pattern to query must be specified with the -IndexPattern parameter. This can be like 'myindex' or 'alerts-*' or 'thisIndex,thatIndex'.\n"
    bail_out
}

# Calculate the max number of pages to pull from page size and max records settings
$PageLimit=(($MaxRecords / $PageSize) + 1)

# Get a new PID ID
$uri = $ESPROTO+"://"+$ESHOST+":"+$ESPORT+"/$IndexPattern/_pit?keep_alive=60m"
$IWRResult = Invoke-WebRequest -Method POST -SkipCertificateCheck -Uri $uri -Headers $Headers
$PIT_ID=($IWRResult.Content|ConvertFrom-Json).id

# Query for initial page of results, generating the body then executing the curl
$BodyJson = @{
    "size"  = $PageSize 
    "query" = $QueryBody
    "sort"  = $SortBody
    "fields" = $FieldsBody
    "_source" = $True
    "pit"     = @{
        "id" = $PIT_ID
        "keep_alive" = "60m"
    }
}

if ($Debug){
    write-debug "Query to execute against index(es):$IndexPattern"
    $BodyJson
	write-output "No more than $PageLimit $PageSize-record page(s) will be loaded, and no more than $MaxRecords records will be returned."
}

#Execute Query against ElasticSearch
$Headers = @{
    "Authorization" = $basicAuthValue
    "Content-Type" = "application/json"
}
$uri = $ESPROTO+"://"+$ESHOST+":"+$ESPORT+"/_search"
$initialRun = $True ; $resultsRemaining = $True

While($initialRun -Or $resultsRemaining){
    $InitialRun = $False
    $QueryResult = $null
    $QueryResult = (Invoke-WebRequest -SkipCertificateCheck -Uri $uri -Method POST -Headers $Headers -Body ($BodyJson|ConvertTo-Json -Depth 100)).Content|ConvertFrom-Json
    if (!$QueryResult.hits){
        If ($Debug){write-output "No Match"}
        bail_out
    }
    $PIT_ID = $QueryResult.pit_id
    $BodyJson.pit.id = $PIT_ID
    $BodyJson["search_after"] = @($QueryResult.hits.hits.sort|select-object -Last 2)

    If ($QueryResult.hits.hits){
        ForEach ($hit in $QueryResult.hits.hits){
            $tmpHash = [Ordered]@{}
            #Convert from PSObject to Ordered Hashtable
            $hit._source.psobject.properties | ForEach-Object { $tmpHash[$_.Name] = $_.Value }
            #Add the fields we search to to the _source.
            $hit.fields.psobject.properties | ForEach-Object { $tmpHash[$_.Name] = $_.Value }
            
            $FinalResults += $tmpHash
        }
    }else{
        $resultsRemaining = $False
        break;
    }

    $PageCount = $PageCount + 1
    If ($Debug){
        write-output "Loaded page $PageCount of results."
    }
    If ($PageCount -ge $PageLimit){
        If ($Debug){
            write-output "Reached PageLimit at $PageCount pages of results."
        }
        write-output "Reached PageLimit at $PageCount pages of results."

        break;
    }
}


#Delete the PIT_ID from ElasticSearch, to free memory.
$uri = $ESPROTO+"://"+$ESHOST+":"+$ESPORT+"/_pit"
$Headers = @{
    "Authorization" = $basicAuthValue
    "Content-Type" = "application/json"
}
$BodyJson = @{
    "id" = $PIT_ID
}
$IWRResult = Invoke-WebRequest -Method DELETE -SkipCertificateCheck -Uri $uri -Headers $Headers -Body ($BodyJson|ConvertTo-Json -Depth 100)


#Handle output
If ($CSV){
    #Output CSV
    $FinalResults|ConvertTo-CSV
}ElseIf($JSON){
    #Output Json
    $FinalResults|ConvertTo-Json -Depth 100
}Else{
    #Output Native Powershell
    $FinalResults
}
