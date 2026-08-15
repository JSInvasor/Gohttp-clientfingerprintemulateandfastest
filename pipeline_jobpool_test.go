package gofire

import (
	"context"
	"reflect"
	"testing"
)

// Every field of a job has to be cleared before it goes back to the pool.
//
// Six of the eight Put sites cleared nothing, and the field that made that a bug
// rather than a leak is blockResult — the one field no caller sets explicitly.
// spraySubmit sets it, and returned its jobs to the pool with it still true
// whenever the context was cancelled. A Send that drew that job got a worker on
// the blocking delivery path, where `job.result <- result` and `<-job.ctx.Done()`
// are both ready once the caller's request has timed out — and Go picks between
// ready cases at random. Half the time the result was dropped and the caller,
// still blocked on the channel Send handed back, waited forever.
//
// Checked by reflection rather than field by field, so a field added later fails
// this instead of quietly joining the ones that were not being cleared.
func TestReleaseJobClearsEveryField(t *testing.T) {
	p := &Pipeline{}
	ch := make(chan *PipelineResult, 1)
	job := &pipelineJob{
		ctx:         context.Background(),
		method:      "POST",
		url:         "https://site.test/",
		body:        []byte("payload"),
		headers:     map[string]string{"X": "1"},
		result:      ch,
		blockResult: true,
	}

	// Every field is non-zero going in, or the assertion below proves nothing.
	v := reflect.ValueOf(*job)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			t.Fatalf("field %q was already zero before the release", v.Type().Field(i).Name)
		}
	}

	p.releaseJob(job)

	v = reflect.ValueOf(*job)
	for i := 0; i < v.NumField(); i++ {
		if !v.Field(i).IsZero() {
			t.Errorf("field %q survived the release: %#v — a reused job carries it into "+
				"the next request", v.Type().Field(i).Name, v.Field(i).Interface())
		}
	}
}
