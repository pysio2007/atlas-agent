package store

import (
	"encoding/json"

	"github.com/sirupsen/logrus"
	bolt "go.etcd.io/bbolt"
)

type Store struct {
	db  *bolt.DB
	log *logrus.Logger
}

func Open(path string, log *logrus.Logger) (*Store, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("state"))
		return err
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	return &Store{db: db, log: log}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) GetProbeID() string {
	var id string
	s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("state"))
		if b == nil {
			return nil
		}
		v := b.Get([]byte("probe_id"))
		if v != nil {
			if err := json.Unmarshal(v, &id); err != nil {
				s.log.WithError(err).Warn("failed to unmarshal probe_id")
			}
		}
		return nil
	})
	return id
}

func (s *Store) SetProbeID(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("state"))
		if err != nil {
			return err
		}
		data, err := json.Marshal(id)
		if err != nil {
			return err
		}
		return b.Put([]byte("probe_id"), data)
	})
}
