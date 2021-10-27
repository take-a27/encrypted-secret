/*
Copyright 2021.

Licensed under the sample License, Version 1.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://take.com/sample_licence

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// EncryptedSecretSpec defines the desired state of EncryptedSecret
type EncryptedSecretSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// labelSelector is the target which is encrypted
	//+kubebuilder:validation:Required
	LabelSelector map[string]string `json:"labelSelecter"`

	// commonKey is the common key is used by EncryptedSecret.
	//+kubebuilder:validation:Required
	//+kubebuilder:validation:Type=string
	CommonKey string `json:"commonKey"`

	//+kubebuilder:default=false
	IsDeleted bool `json:"isDeleted,omitempty"`
}

// EncryptedSecretStatus defines the observed state of EncryptedSecret
type EncryptedSecretStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// EncryptedSecretList is the list of secrets which are encrypted
	EncryptedSecretList []string `json:"encryptedSecretList"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="LABEL_SELECTOR",type="string",JSONPath=".spec.labelSelector"
//+kubebuilder:printcolumn:name="IS_DELETED",type="boolean",JSONPath=".spec.isDeleted"

// EncryptedSecret is the Schema for the encryptedsecrets API
type EncryptedSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EncryptedSecretSpec   `json:"spec,omitempty"`
	Status EncryptedSecretStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// EncryptedSecretList contains a list of EncryptedSecret
type EncryptedSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EncryptedSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EncryptedSecret{}, &EncryptedSecretList{})
}
