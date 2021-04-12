@load base/frameworks/sumstats

event zeek_init()
{
    local r1 = SumStats::Reducer($stream = "response_all", $apply = set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream = "response_404", $apply = set(SumStats::SUM));
    local r3 = SumStats::Reducer($stream = "response_unique404", $apply = set(SumStats::UNIQUE));
    SumStats::create([ $name = "response_detect", $epoch = 10min, $reducers = set(r1, r2, r3),
                        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
                          local t1 = result["response_all"];
                          local t2 = result["response_404"];
                          local t3 = result["response_unique404"];
                          if (t2$sum > 2)
                          {
                              if (t2$sum / t1$sum > 0.2)
                              {
                                  if (t3$unique / t2$sum > 0.5)
                                  {
                                      print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, t2$sum, t3$unique);
                                  }
                              }
                          }
                      }
                    ]);
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
    SumStats::observe("response_all", SumStats::Key($host = c$id$orig_h), SumStats::Observation($num = 1));
    if (code == 404)
    {
        SumStats::observe("response_404", SumStats::Key($host = c$id$orig_h), SumStats::Observation($num = 1));
        SumStats::observe("response_unique404", SumStats::Key($host = c$id$orig_h), SumStats::Observation($str = c$http$uri));
    }
}
