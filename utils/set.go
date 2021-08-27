package utils

type Set struct {
	m map[string]struct{}
}

func NewSet(values ...string) *Set {
	s := &Set{}
	s.m = make(map[string]struct{})
	for _, v := range values {
		s.Add(v)
	}
	return s
}

func (s *Set) Add(value string) {
	s.m[value] = struct{}{}
}

func (s *Set) Remove(value string) {
	delete(s.m, value)
}

func (s *Set) Contains(value string) bool {
	_, c := s.m[value]
	return c
}

func (s *Set) HasIntersection(s2 []string) bool {
	for _, v := range s2 {
		if s.Contains(v) {
			return true
		}
	}
	return false
}
