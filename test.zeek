@load base/frameworks/sumstats
global total : count = 0;

event zeek_init()
{
    local r1 = SumStats::Reducer($stream = "404Response", $apply = set(SumStats::SUM));
    SumStats::create([ $name = "ResponseDetect", $epoch = 10min, $reducers = set(r1),
                        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
                          local r = result["404Response"];
                          if (r$sum > 2)
                          {
                              if (r$sum / total > 0.2)
                              {
                                  if (r$unique / r$sum > 0.5)
                                  {
                                      print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, r$sum, r$unique);
                                  }
                              }
                          }
                      }
                    ]);
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
    total += 1;
    if (code == 404)
    {
        SumStats::observe("404response", SumStats::Key($host = c$id$orig_h), SumStats::Observation($str = reason));
    }
}