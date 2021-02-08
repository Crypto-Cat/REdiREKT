@load policy/protocols/http/bodies
@load base/utils/urls
@load base/utils/patterns

redef HTTP::hook_reply_bodies = T;

module HttpURLExtract;

export {
    redef enum Log::ID += { LOG };
    redef Reporter::errors_to_stderr=F;

    type Info: record {
        ts:         time     &log;
        uid:        string   &log;
        url:        string   &log;
        redir_url:  string   &log;
        redir_type: string   &log;
    };

    ## A potential redirect
    type PotentialRedirect: record
    {
        ts:         time;     ##< HTTP request timestamp.
        uid:        string;   ##< UID of the request.
        url:        string;   ##< URL of the page being scanned.
        redir_url:  string;   ##< URL of the link found in HTML/JS.
        redir_type: string;   ##< Type of redirection that occurred.
    };

    type redir_array: set[PotentialRedirect];

    type set_of_strings: set[string,string];

    global log_redir: event(rec: Info);

    global redir_map = redir_array();

    global seen_redirections = set_of_strings();
}

event zeek_init()
{
    Log::create_stream(HttpURLExtract::LOG, [$columns=Info, $ev=log_redir, $path="redirections"]);
}

## Log the redirects to file.
function log_redirect(redir_chain: PotentialRedirect)
{
    local i: Info;
    i$ts = redir_chain$ts;
    i$uid = redir_chain$uid;
    i$url = redir_chain$url;
    i$redir_url = redir_chain$redir_url;
    i$redir_type = redir_chain$redir_type;

    Log::write(HttpURLExtract::LOG, i);
}

function process_redir_type(c: connection, matched_patterns: string_set, redir_type: string)
{
    for (matched_pattern in matched_patterns){
        # Only process matches that have at least 5 chars
        if(|matched_pattern| >= 5){
            # More fine-tuned regex to grab URLs
            local urls = find_all(matched_pattern, /[a-zA-Z\-]{3,5}:\/\/([[:alnum:]\.\-\_]+)(:[:digit:])?/i);
            for (url in urls){
                # Format the URLs
                local redir_from = to_lower(gsub(c$http$host, /([a-zA-Z\-]{3,5}:\/\/)?(w{3}\.)?/, ""));
                local redir_to = to_lower(gsub(url, /([a-zA-Z\-]{3,5}:\/\/)?(w{3}\.)?/, ""));

                # We don't want to duplicate any Unknown URLs that were in iFrames/JS/HTML
                if (redir_type != "Unknown" || [redir_from, redir_to] !in seen_redirections){
                    # Add this URL to the list of those observed
                    add seen_redirections[redir_from, redir_to];

                    # Create a potential redirection object and complete the values
                    local redir_chain: PotentialRedirect;
                    redir_chain$ts = c$http$ts;
                    redir_chain$uid = c$http$uid;
                    redir_chain$url = redir_from;
                    redir_chain$redir_url = redir_to;
                    redir_chain$redir_type = redir_type;
                    # If this chain hasn't been added
                    if (redir_chain !in redir_map){
                        # Add it to the redirection map
                        add redir_map[redir_chain];
                        # Log the redirection chains to a file
                        log_redirect(redir_chain);
                    }
                
                    # print redir_chain;
                    # print "Matched string: " + regex$str;
                    # print redir_type + ": " + hostname;

                    # If an iFrame was found but no URLs were extracted, it's obfuscated
                    # if ((|matched_urls|) == 0 && redir_type == "iFrame"){
                        # print "OBFUSCATED iFRAME:";
                        # print regex$str;
                        # print "";
                    # }
                    
                }
            }
        }
    }
}

## Reassemble the HTTP body of replies and look for URLs.
event http_body(c: connection, is_orig: bool, data: string, size: count)
{
    # Make sure we've got a hostname
    if (c$http?$host){
        # Uncomment to see how the data looks.
        # print data;
        # print "--------------------------------------------------------------";

        # Which redirections are we going to exclude?
        # local whitelist = /(google(apis)?(\-analytics)?|\.facebook|microsoft|bing|yahoo|duckduckgo|baidu|ask|aol|wolframalpha|yandex|adultfriendfinder)\.|localhost|ya\.ru/i;
        # local is_whitelisted = match_pattern(to_lower(c$http$host), whitelist);

        local regex_types: table[string] of string_set;

        # Note that we need to deal with more possible quotations and we can't match obfuscated scripts/URLs
        local q = /[\'\"[:space:]]*/i;

        # Pattern to match window.location redirection in JavaScript
        regex_types["JavaScript"] = find_all(data, /(\<[:space:]*script[:space:]*\>?.*\<?[:space:]*\/[:space:]*script[:space:]*\>)/i | /(window|document)[:space:]*\.[:space:]*(location|open)?[:space:]*\.?[:space:]*(href|hostname|replace|assign|write|[a-z0-9]*)?[:space:]*/i & q & /.*/i & q);
        
        # Pattern to match meta http-equiv Refresh redirection in HTML
        regex_types["HTML"] = find_all(data, /http-equiv[:space:]*=/i & q & /Refresh/i & q & /.*\/?\>/i | /\<[:space:]*(form|a|p|img[:space:]*src).*\>/i);

        # Pattern to match iFrame redirection
        regex_types["iFrame"] = find_all(data, /\<[:space:]*iframe[:space:]*\>?.*\>/i);

        # Pattern to match Base64 encoded-strings
        regex_types["Base64"] = find_all(data, /\(?[:space:]*[\'\"][:space:]*[a-z0-9\+\/]{32,}\={0,4}?[:space:]*[\'\"][:space:]*\)?\;/i);

        # Pattern to match concatenated encoded-strings
        regex_types["Concat"] = find_all(data, /[a-z0-9]+[:space:]*\=([:space:]*[\'\"][:space:]*[a-z0-9\/\.\:\-\_\=\+]+[:space:]*[\'\"][:space:]*\+[:space:]*)+[\'\"][:space:]*[a-z0-9\/\.\:\-\_\=\+]*[:space:]*[\'\"]\;/i);

        # Process the known redirect types
        for(redir_type in regex_types){
            # If we got at least one result
            if(|regex_types[redir_type]| >= 1){
                # For each of the matches we found
                for (match in regex_types[redir_type]){
                    if(|match| > 5){
                        if(redir_type == "Base64"){
                            # Decode the base64
                            match = gsub(match, q, "");
                            match = decode_base64(match);
                        }else if(redir_type == "Concat"){
                            # Join the string together and strip unnessesary chars
                            match = gsub(match, /[\'\"\+[:space:]]*/i, "");
                        }
                        local matched_urls = find_all_urls(match);
                        # Get the redirections for this regex type
                        process_redir_type(c, matched_urls, redir_type);
                    }
                }
            }
        }
        # Catch anything we missed
        local unknown_urls = find_all_urls(data);

        # Get the redirections for this regex type
        process_redir_type(c, unknown_urls, "Unknown");
    }
}