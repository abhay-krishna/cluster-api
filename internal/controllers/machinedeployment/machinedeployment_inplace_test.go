package machinedeployment

import (
	"testing"

	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/pointer"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	mdName     = "my-md"
	msName     = "my-ms"
	version128 = "v1.28.0"
	version129 = "v1.29.0"
)

func getMachineDeployment(name string, version string, replicas int32) *clusterv1.MachineDeployment {
	return &clusterv1.MachineDeployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: clusterv1.MachineDeploymentSpec{
			Strategy: &clusterv1.MachineDeploymentStrategy{
				Type: clusterv1.InPlaceMachineDeploymentStrategyType,
			},
			Replicas: pointer.Int32(replicas),
			Template: clusterv1.MachineTemplateSpec{
				Spec: clusterv1.MachineSpec{
					ClusterName: "my-cluster",
					Version:     pointer.String(version),
				},
			},
		},
	}
}

func getMachineSet(name string, version string, replicas int32) *clusterv1.MachineSet {
	return &clusterv1.MachineSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: clusterv1.MachineSetSpec{
			Replicas: pointer.Int32(replicas),
			Template: clusterv1.MachineTemplateSpec{
				Spec: clusterv1.MachineSpec{
					ClusterName: "my-cluster",
					Version:     pointer.String(version),
				},
			},
		},
	}
}

func TestRolloutInPlace(t *testing.T) {
	testCases := []struct {
		name               string
		machineDeployment  *clusterv1.MachineDeployment
		msList             []*clusterv1.MachineSet
		annotationExpected bool
		expectErr          bool
	}{
		{
			name:               "MD template matches MS template",
			machineDeployment:  getMachineDeployment(mdName, version128, 2),
			msList:             []*clusterv1.MachineSet{getMachineSet(msName, version128, 2)},
			annotationExpected: false,
			expectErr:          false,
		},
		{
			name:               "MD template doesn't MS template",
			machineDeployment:  getMachineDeployment(mdName, version128, 2),
			msList:             []*clusterv1.MachineSet{getMachineSet(msName, version129, 2)},
			annotationExpected: true,
			expectErr:          true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			resources := []client.Object{
				tc.machineDeployment,
			}

			for key := range tc.msList {
				resources = append(resources, tc.msList[key])
			}

			r := &Reconciler{
				Client:   fake.NewClientBuilder().WithObjects(resources...).Build(),
				recorder: record.NewFakeRecorder(32),
			}

			err := r.rolloutInPlace(ctx, tc.machineDeployment, tc.msList)
			if tc.expectErr {
				g.Expect(err).To(HaveOccurred())
			}

			_, ok := tc.machineDeployment.Annotations[clusterv1.MachineDeploymentInPlaceUpgradeAnnotation]
			g.Expect(ok).To(Equal(tc.annotationExpected))
		})
	}

}
