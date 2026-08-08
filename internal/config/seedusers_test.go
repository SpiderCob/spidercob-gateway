package config

import (
	"reflect"
	"strings"
	"testing"
)

// TestParseSeedUsersCSV exercises the pure CSV-parsing/validation logic
// directly (issue #21) -- no file I/O, same "pure, directly testable"
// posture ValidateNode already established for issue #15.
func TestParseSeedUsersCSV(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []SeedUser
		wantErr bool
	}{
		{
			name: "valid, username+password+groups",
			in: "username,password,groups\n" +
				"alice,s3cret,engineering;support\n" +
				"bob,hunter2,engineering\n",
			want: []SeedUser{
				{Username: "alice", Password: "s3cret", Groups: []string{"engineering", "support"}},
				{Username: "bob", Password: "hunter2", Groups: []string{"engineering"}},
			},
		},
		{
			name: "no groups column at all",
			in: "username,password\n" +
				"alice,s3cret\n",
			want: []SeedUser{
				{Username: "alice", Password: "s3cret"},
			},
		},
		{
			name: "empty groups cell",
			in: "username,password,groups\n" +
				"alice,s3cret,\n",
			want: []SeedUser{
				{Username: "alice", Password: "s3cret"},
			},
		},
		{
			name: "columns in any order, case-insensitive header",
			in: "Groups,Password,Username\n" +
				"engineering,s3cret,alice\n",
			want: []SeedUser{
				{Username: "alice", Password: "s3cret", Groups: []string{"engineering"}},
			},
		},
		{
			name: "whitespace around values is trimmed",
			in: "username,password,groups\n" +
				" alice , s3cret , engineering ; support \n",
			want: []SeedUser{
				{Username: "alice", Password: "s3cret", Groups: []string{"engineering", "support"}},
			},
		},
		{
			name:    "missing username header column",
			in:      "password,groups\nalice,eng\n",
			wantErr: true,
		},
		{
			name:    "missing password header column",
			in:      "username,groups\nalice,eng\n",
			wantErr: true,
		},
		{
			name:    "empty username value",
			in:      "username,password\n,s3cret\n",
			wantErr: true,
		},
		{
			name:    "empty password value",
			in:      "username,password\nalice,\n",
			wantErr: true,
		},
		{
			name:    "duplicate username within the file",
			in:      "username,password\nalice,s3cret\nalice,other\n",
			wantErr: true,
		},
		{
			name:    "header only, no data rows",
			in:      "username,password\n",
			want:    nil,
			wantErr: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseSeedUsersCSV(strings.NewReader(c.in))
			if c.wantErr {
				if err == nil {
					t.Fatalf("ParseSeedUsersCSV(%q): got nil error, want non-nil", c.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSeedUsersCSV(%q): %v", c.in, err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("ParseSeedUsersCSV(%q) = %+v, want %+v", c.in, got, c.want)
			}
		})
	}
}
