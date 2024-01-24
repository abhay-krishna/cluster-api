package machinedeployment

import (
	"context"

	"github.com/pkg/errors"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	ctrl "sigs.k8s.io/controller-runtime"

	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/util/annotations"
)

func (r *Reconciler) rolloutInPlace(ctx context.Context, md *clusterv1.MachineDeployment, msList []*clusterv1.MachineSet) (reterr error) {
	log := ctrl.LoggerFrom(ctx)

	// For in-place upgrade, we shouldn't try to create a new MachineSet as that would trigger a rollout.
	// Instead, we should try to get latest MachineSet that matches the MachineDeployment.Spec.Template/
	// If no such MachineSet exists yet, this means the MachineSet hasn't been in-place upgraded yet.
	// The external in-place upgrade implementer is responsible for updating the latest MachineSet's template
	// after in-place upgrade of all worker nodes belonging to the MD is complete.
	// Once the MachineSet is updated, this function will return the latest MachineSet that matches the
	// MachineDeployment template and thus we can deduce that the in-place upgrade is complete.
	newMachineSet, oldMachineSets, err := r.getAllMachineSetsAndSyncRevision(ctx, md, msList, false)
	if err != nil {
		return err
	}

	defer func() {
		allMSs := append(oldMachineSets, newMachineSet)

		// Always attempt to sync the status
		err := r.syncDeploymentStatus(allMSs, newMachineSet, md)
		reterr = kerrors.NewAggregate([]error{reterr, err})
	}()

	if newMachineSet == nil {
		log.Info("Changes detected, InPlace upgrade strategy detected, adding the annotation")
		annotations.AddAnnotations(md, map[string]string{clusterv1.MachineDeploymentInPlaceUpgradeAnnotation: "true"})
		return errors.New("new MachineSet not found. This most likely means that the in-place upgrade hasn't finished yet")
	}

	return r.sync(ctx, md, msList)
}
