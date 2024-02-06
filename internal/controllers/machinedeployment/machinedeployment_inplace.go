package machinedeployment

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"

	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/internal/controllers/machinedeployment/mdutil"
	"sigs.k8s.io/cluster-api/util/annotations"
)

func (r *Reconciler) rolloutInPlace(ctx context.Context, md *clusterv1.MachineDeployment, msList []*clusterv1.MachineSet) (reterr error) {
	log := ctrl.LoggerFrom(ctx)

	// If there are no MachineSets for a MachineDeployment, either this is a create operation for a new
	// MachineDeployment or the MachineSets were manually deleted. In either case, a new MachineSet should be created
	// as there are no MachineSets that can be in-place upgraded.
	// If there are already MachineSets present, we shouldn't try to create a new MachineSet as that would trigger a rollout.
	// Instead, we should try to get latest MachineSet that matches the MachineDeployment.Spec.Template
	// If no such MachineSet exists yet, this means the MachineSet hasn't been in-place upgraded yet.
	// The external in-place upgrade implementer is responsible for updating the latest MachineSet's template
	// after in-place upgrade of all worker nodes belonging to the MD is complete.
	// Once the MachineSet is updated, this function will return the latest MachineSet that matches the
	// MachineDeployment template and thus we can deduce that the in-place upgrade is complete.
	newMachineSetNeeded := len(msList) == 0
	newMachineSet, oldMachineSets, err := r.getAllMachineSetsAndSyncRevision(ctx, md, msList, newMachineSetNeeded)
	if err != nil {
		return err
	}

	allMSs := oldMachineSets

	if newMachineSet == nil {
		log.Info("Changes detected, InPlace upgrade strategy detected, adding the annotation")
		annotations.AddAnnotations(md, map[string]string{clusterv1.MachineDeploymentInPlaceUpgradeAnnotation: "true"})
	} else if !annotations.HasAnnotation(md, clusterv1.MachineDeploymentInPlaceUpgradeAnnotation) {
		// If in-place upgrade annotation is no longer present, attempt to scale up the new MachineSet if necessary
		// and scale down the old MachineSets if necessary.
		// Note that if there are no scaling operations required, this else if block will be a no-op.

		allMSs = append(allMSs, newMachineSet)

		// Scale up, if we can.
		if err := r.reconcileNewMachineSet(ctx, allMSs, newMachineSet, md); err != nil {
			return err
		}

		if err := r.syncDeploymentStatus(allMSs, newMachineSet, md); err != nil {
			return err
		}

		// Scale down, if we can.
		if err := r.reconcileOldMachineSets(ctx, allMSs, oldMachineSets, newMachineSet, md); err != nil {
			return err
		}
	}

	if err := r.syncDeploymentStatus(allMSs, newMachineSet, md); err != nil {
		return err
	}

	if mdutil.DeploymentComplete(md, &md.Status) {
		if err := r.cleanupDeployment(ctx, oldMachineSets, md); err != nil {
			return err
		}
	}

	return nil
}
