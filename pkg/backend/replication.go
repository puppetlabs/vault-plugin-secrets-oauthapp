package backend

import (
	"github.com/hashicorp/vault/sdk/helper/consts"
)

func (b *backend) ownsStorage() bool {
	sysView := b.System()

	// In test, we may not have a system view at all. We expect our storage to
	// be ephemeral in this case.
	if sysView == nil {
		return true
	}

	replicationState := sysView.ReplicationState()

	return (sysView.LocalMount() || !replicationState.HasState(consts.ReplicationPerformanceSecondary)) &&
		!replicationState.HasState(consts.ReplicationDRSecondary) &&
		!replicationState.HasState(consts.ReplicationPerformanceStandby)
}
